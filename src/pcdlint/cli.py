"""CLI entry point for pcdlint."""

import argparse
import ast
import subprocess
import sys
from pathlib import Path
from typing import Any

from rich.console import Console
from rich.table import Table

from pcdlint import __version__, config
from pcdlint.analyzer import analyze_path_ex
from pcdlint.fixer import apply_edits
from pcdlint.rules import KNOWN_RULE_IDS, RULE_SHORT_DESCRIPTIONS

# Shown as the tool's informationUri and every rule's helpUri in SARIF.
_REPO_URL = "https://github.com/ZhiwarSajadi/pcdlint"


def _analyze_paths(paths: list, select: frozenset | None,
                   ignore: frozenset | None) -> tuple[list, list[str]]:
    """Analyze every path, keeping diagnostics and blocking errors apart."""
    diagnostics: list = []
    errors: list[str] = []
    for path_str in paths:
        found, path_errors = analyze_path_ex(Path(path_str), select=select,
                                             ignore=ignore)
        diagnostics.extend(found)
        errors.extend(path_errors)
    return diagnostics, errors


def _apply_fixes(diagnostics: list) -> tuple[int, int, list[str]]:
    """Rewrite every file that carries mechanical fixes, in place.

    Returns ``(files changed, findings with no fix, errors)``. A rewrite that
    no longer parses is reported and skipped: losing a finding is recoverable,
    corrupting a source file is not.
    """
    by_file: dict[str, list] = {}
    for diagnostic in diagnostics:
        by_file.setdefault(diagnostic.file_path, []).append(diagnostic)

    changed = 0
    skipped = 0
    errors: list[str] = []
    for file_path, found in by_file.items():
        skipped += sum(1 for d in found if not d.edits)
        edits = [edit for d in found for edit in d.edits]
        if not edits:
            continue
        path = Path(file_path)
        try:
            source = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError) as exc:
            errors.append(f"cannot re-read {path}: {exc}")
            continue
        fixed = apply_edits(source, edits)
        if fixed == source:
            continue
        try:
            ast.parse(fixed, filename=str(path))
        except SyntaxError:
            errors.append(f"autofix for {path} produced invalid syntax; "
                          f"file left unchanged")
            continue
        try:
            path.write_text(fixed, encoding="utf-8")
        except OSError as exc:
            errors.append(f"cannot write {path}: {exc}")
            continue
        changed += 1
    return changed, skipped, errors


def _git_output(args: list) -> tuple[str, str]:
    """Run git; returns ``(stdout, error)``, with ``error`` empty on success."""
    try:
        result = subprocess.run(["git", *args], capture_output=True,
                                text=True, encoding="utf-8", errors="replace",
                                check=False)
    except OSError as exc:
        return "", str(exc)
    if result.returncode != 0:
        detail = (result.stderr or "").strip()
        return "", detail or f"exit status {result.returncode}"
    return result.stdout, ""


def _absolute(path_text: str, root: Path) -> str:
    """Resolve ``path_text`` against ``root`` as an absolute POSIX path."""
    path = Path(path_text)
    if not path.is_absolute():
        path = root / path
    return path.resolve().as_posix()


def _parse_added_lines(patch: str, root: Path) -> dict[str, set[int]]:
    """Absolute POSIX path -> the line numbers each ``@@`` hunk adds."""
    changed: dict[str, set[int]] = {}
    current: str | None = None
    for line in patch.splitlines():
        if line.startswith("+++ "):
            target = line[4:].strip()
            current = None if target == "/dev/null" else _absolute(target, root)
        elif line.startswith("@@") and current is not None:
            fields = line.split()
            if len(fields) < 3 or not fields[2].startswith("+"):
                continue
            start_text, _, count_text = fields[2][1:].partition(",")
            try:
                start = int(start_text)
                count = int(count_text) if count_text else 1
            except ValueError:
                continue
            if count > 0:
                changed.setdefault(current, set()).update(
                    range(start, start + count))
    return changed


def _filter_to_changed(diagnostics: list, ref: str) -> tuple[list, list[str]]:
    """Keep only findings on lines the working tree changed since ``ref``.

    A failure to diff is an error, not "no findings": reporting a clean run
    because git was unavailable would be the linter lying about the code.
    """
    top, top_error = _git_output(["rev-parse", "--show-toplevel"])
    if top_error:
        return [], [f"--diff requires git: {top_error}"]
    patch, diff_error = _git_output(
        ["diff", "--unified=0", "--no-color", "--no-ext-diff", "--no-prefix", ref])
    if diff_error:
        return [], [f"git diff against {ref!r} failed: {diff_error}"]

    changed = _parse_added_lines(patch, Path(top.strip()))
    return [
        d for d in diagnostics
        if d.lineno in changed.get(_absolute(d.file_path, Path.cwd()), ())
    ], []


def main() -> int:
    # Ensure UTF-8 output encoding across platforms (prevent Windows charmap/cp1252
    # errors). sys.stdout is typed TextIO but may be a wrapper object at runtime, so
    # reconfigure() is probed duck-typed exactly as before.
    out: Any = sys.stdout
    err: Any = sys.stderr
    if hasattr(out, "reconfigure"):
        try:
            out.reconfigure(encoding="utf-8", errors="replace")
            err.reconfigure(encoding="utf-8", errors="replace")
        # reconfigure() fails only when the stream refuses a new encoding, and a
        # lossy stream beats a dead run. Anything else is a genuine bug worth surfacing.
        except (OSError, ValueError, AttributeError):
            pass

    parser = argparse.ArgumentParser(
        prog="pcdlint",
        description="Static Taint Linter for Prompt-Cache Determinism",
        epilog="Exit codes: 0 = clean, 1 = findings (add --fail-on-warn to fail on "
               "warnings), 2 = a path could not be analyzed (missing, not Python, "
               "undecodable, or unparseable).",
    )
    parser.add_argument("paths", nargs="*", help="File or directory paths to check")
    parser.add_argument(
        "--format", choices=["text", "json", "sarif"], default="text",
        help="Output format: text, json, or sarif 2.1.0 for GitHub Code "
             "Scanning (default: text)",
    )
    parser.add_argument(
        "--fail-on-warn", action="store_true",
        help="Exit with code 1 if any WARNING is found",
    )
    parser.add_argument(
        "--fix", action="store_true",
        help="Apply safe automatic fixes (PCL002 sort_keys, PCL003 sorted) "
             "in place, then report what still fails",
    )
    parser.add_argument(
        "--select", action="append", metavar="RULES", default=None,
        help="Comma-separated rule ids to run (repeatable); overrides "
             "[tool.pcdlint] select",
    )
    parser.add_argument(
        "--ignore", action="append", metavar="RULES", default=None,
        help="Comma-separated rule ids to skip (repeatable); overrides "
             "[tool.pcdlint] ignore",
    )
    parser.add_argument(
        "--diff", nargs="?", const="HEAD", default=None, metavar="REF",
        help="Only report findings whose own line the working tree changed "
             "since REF in git (default: HEAD). A finding on an untouched "
             "line stays hidden even when the value it points at changed.",

    )
    parser.add_argument(
        "--version", action="version", version=f"pcdlint {__version__}",
    )
    args = parser.parse_args()

    try:
        select = config.parse_rule_list(args.select, "--select") if args.select else None
        ignore = config.parse_rule_list(args.ignore, "--ignore") if args.ignore else None
    except config.ConfigError as exc:
        print(f"pcdlint: error: {exc}", file=sys.stderr)
        return 2

    if not args.paths:
        parser.print_help()
        return 0

    raw_paths = list(args.paths)
    # Support both `pcdlint check [paths...]` and `pcdlint [paths...]`
    if raw_paths and raw_paths[0] == "check":
        raw_paths = raw_paths[1:]
        if not raw_paths:
            raw_paths = ["."]

    all_diagnostics, all_errors = _analyze_paths(raw_paths, select, ignore)

    if args.diff is not None:
        # Before --fix: PR CI wants only the lines a change introduced fixed.
        all_diagnostics, diff_errors = _filter_to_changed(all_diagnostics,
                                                           args.diff)
        all_errors.extend(diff_errors)

    if args.fix:
        changed, skipped, fix_errors = _apply_fixes(all_diagnostics)
        all_errors.extend(fix_errors)
        if changed:
            # Re-read so the report and the exit code describe what is on
            # disk now, not what was there before the rewrite.
            all_diagnostics, recheck_errors = _analyze_paths(raw_paths, select, ignore)
            all_errors.extend(recheck_errors)
        if changed or skipped:
            print(
                f"pcdlint: fixed {changed} file(s); "
                f"{skipped} finding(s) have no automatic fix",
                file=sys.stderr,
            )

    all_diagnostics.sort(key=lambda d: (d.file_path, d.lineno, d.col_offset))

    if args.format == "json":
        _print_json(all_diagnostics)
    elif args.format == "sarif":
        # Always emitted, even with no findings: an empty results array is
        # valid SARIF and lets Code Scanning clear stale annotations.
        _print_sarif(all_diagnostics)
    elif all_diagnostics or not all_errors:
        _print_text(all_diagnostics)

    # A path we could not analyze must never look clean, so report it loudly.
    # dict.fromkeys dedupes: one broken config produces one message, not one
    # per file it touches.
    for message in dict.fromkeys(all_errors):
        print(f"pcdlint: error: {message}", file=sys.stderr)

    if all_errors:
        return 2

    has_errors = any(d.severity == "ERROR" for d in all_diagnostics)
    has_warnings = any(d.severity == "WARNING" for d in all_diagnostics)

    if has_errors:
        return 1
    if args.fail_on_warn and has_warnings:
        return 1
    return 0


def _print_json(diagnostics: list) -> None:
    import json
    data = []
    for d in diagnostics:
        data.append({
            "file_path": d.file_path,
            "lineno": d.lineno,
            "col_offset": d.col_offset,
            "rule_id": d.rule_id,
            "rule_name": d.rule_name,
            "message": d.message,
            "fix_suggestion": d.fix_suggestion,
            "severity": d.severity,
        })
    print(json.dumps(data, indent=2, sort_keys=True))


def _sarif_uri(file_path: str) -> str:
    """A POSIX path relative to the working directory, as Code Scanning wants."""
    path = Path(file_path)
    if path.is_absolute():
        try:
            path = path.relative_to(Path.cwd())
        except ValueError:
            pass
    return path.as_posix()


def _print_sarif(diagnostics: list) -> None:
    import json

    rules = [
        {
            "id": rule_id,
            "shortDescription": {"text": RULE_SHORT_DESCRIPTIONS[rule_id]},
            "helpUri": f"{_REPO_URL}#readme",
        }
        for rule_id in sorted(KNOWN_RULE_IDS)
    ]
    results = [
        {
            "ruleId": d.rule_id,
            "level": "error" if d.severity == "ERROR" else "warning",
            "message": {"text": d.message},
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {"uri": _sarif_uri(d.file_path)},
                        # SARIF columns are 1-based; ast reports 0-based.
                        "region": {
                            "startLine": d.lineno,
                            "startColumn": d.col_offset + 1,
                        },
                    }
                }
            ],
        }
        for d in diagnostics
    ]
    print(json.dumps(
        {
            "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "pcdlint",
                            "version": __version__,
                            "informationUri": _REPO_URL,
                            "rules": rules,
                        }
                    },
                    "results": results,
                }
            ],
        },
        indent=2,
    ))


def _print_text(diagnostics: list) -> None:
    console = Console()
    if not diagnostics:
        console.print("[green]No issues found![/green]")
        return
    for d in diagnostics:
        severity_color = "red" if d.severity == "ERROR" else "yellow"
        console.print(
            f"[{severity_color}][{d.rule_id}] {d.rule_name}[/{severity_color}] "
            f"[bold]{d.file_path}:{d.lineno}:{d.col_offset}[/bold] - {d.message}"
        )
        console.print(f"    [bold yellow]💡 Fix:[/bold yellow] {d.fix_suggestion}")
        console.print()
    table = Table(title="Summary")
    table.add_column("Metric", style="cyan")
    table.add_column("Count", style="green")
    error_count = sum(1 for d in diagnostics if d.severity == "ERROR")
    warn_count = sum(1 for d in diagnostics if d.severity == "WARNING")
    table.add_row("Errors", str(error_count))
    table.add_row("Warnings", str(warn_count))
    table.add_row("Total", str(len(diagnostics)))
    console.print(table)


if __name__ == "__main__":
    sys.exit(main())

