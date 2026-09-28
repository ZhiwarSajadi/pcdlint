"""CLI entry point for pcdlint."""

import argparse
import ast
import subprocess
import sys
from pathlib import Path
from typing import Any

from rich.console import Console
from rich.markup import escape
from rich.table import Table

from pcdlint import __version__, config
from pcdlint.analyzer import analyze_path_ex
from pcdlint.fixer import apply_edits
from pcdlint.rules import KNOWN_RULE_IDS, RULE_SEVERITIES, RULE_SHORT_DESCRIPTIONS

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
            # Bytes in, bytes out: --fix must change only the spans it was
            # asked to change. Text-mode read/write translates newlines
            # through os.linesep (rewriting every line of an LF file on
            # Windows), and a BOM stripped by the analyzer would come back as
            # a parse error here unless it is put back on write.
            data = path.read_bytes()
        except OSError as exc:
            errors.append(f"cannot re-read {path}: {exc}")
            continue
        try:
            source = data.decode("utf-8-sig")
        except UnicodeDecodeError as exc:
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
            bom = b"\xef\xbb\xbf" if data.startswith(b"\xef\xbb\xbf") else b""
            path.write_bytes(bom + fixed.encode("utf-8"))
        except OSError as exc:
            errors.append(f"cannot write {path}: {exc}")
            continue
        changed += 1
    return changed, skipped, errors


def _git_output(args: list) -> tuple[str, str]:
    """Run git; returns ``(stdout, error)``, with ``error`` empty on success."""
    try:
        # quotePath off: git octal-escapes non-ASCII paths by default, so the
        # header reads ``+++ "caf\303\251.py"`` and never matches the real
        # file -- which silently dropped every finding in it.
        result = subprocess.run(
            ["git", "-c", "core.quotePath=false", *args], capture_output=True,
            text=True, encoding="utf-8", errors="replace", check=False)
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


def _hunk_span(spec: str) -> tuple[int, int] | None:
    """``(start, count)`` of one ``@@ -a,b +c,d @@`` side, or None if malformed."""
    start_text, _, count_text = spec.partition(",")
    try:
        start = int(start_text)
        count = int(count_text) if count_text else 1
    except ValueError:
        return None
    return start, count


def _parse_added_lines(patch: str, root: Path) -> dict[str, set[int]]:
    """Absolute POSIX path -> the line numbers each ``@@`` hunk adds.

    The body is consumed against the counts in its own header, so a content
    line that merely *looks* like a file header cannot steal the file from
    the hunks that follow it: an added line whose text is ``++ foo`` renders
    as ``+++ foo``, and a removed line whose text is ``-- x`` renders as
    ``--- x``.
    """
    changed: dict[str, set[int]] = {}
    current: str | None = None
    # Lines still owed by the hunk being read; both 0 between hunks, which
    # is the only place a real +++ header can appear.
    old_left = 0
    new_left = 0
    for line in patch.splitlines():
        if old_left > 0 or new_left > 0:
            if line.startswith("\\"):
                continue  # "\ No newline at end of file" is not a body line
            if line.startswith("+"):
                new_left -= 1
            elif line.startswith("-"):
                old_left -= 1
            else:  # context line: it is part of both the old and the new file
                old_left -= 1
                new_left -= 1
            continue
        if line.startswith("+++ "):
            target = line[4:].strip()
            current = None if target == "/dev/null" else _absolute(target, root)
        elif line.startswith("@@") and current is not None:
            fields = line.split()
            if len(fields) < 3 or not fields[2].startswith("+"):
                continue
            span = _hunk_span(fields[2])
            if span is None:
                continue
            start, count = span
            if count > 0:
                changed.setdefault(current, set()).update(
                    range(start, start + count))
            new_left = count
            old = _hunk_span(fields[1])
            old_left = old[1] if old else 0
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

    root = Path(top.strip())
    changed = _parse_added_lines(patch, root)

    # ``git diff REF`` never mentions a file nobody has added, so a brand-new
    # file reported clean -- the exact false clean exit 2 exists to prevent.
    # Untracked files count as wholly new: every line in one was introduced
    # by this change. --exclude-standard keeps .gitignore'd files out, and -z
    # NUL-separates so no name can be mangled by quoting or by a newline.
    others, others_error = _git_output(
        ["ls-files", "-z", "--others", "--exclude-standard", "--full-name"])
    if others_error:
        return [], [f"--diff could not list untracked files: {others_error}"]
    untracked = {_absolute(name, root) for name in others.split("\0") if name}

    return [
        d for d in diagnostics
        if (path := _absolute(d.file_path, Path.cwd())) in untracked
        or d.lineno in changed.get(path, ())
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
        # An empty --ignore means "ignore nothing", which is not a clean run
        # hiding behind a typo: it leaves every rule on.
        ignore = (config.parse_rule_list(args.ignore, "--ignore", allow_empty=True)
                  if args.ignore else None)
    except config.ConfigError as exc:
        print(f"pcdlint: error: {exc}", file=sys.stderr)
        return 2

    if not args.paths:
        parser.print_help()
        return 0

    raw_paths = list(args.paths)
    # Support both `pcdlint check [paths...]` and `pcdlint [paths...]`.
    # ``check`` is only a subcommand when nothing on disk is called that;
    # otherwise the token was dropped and ``.`` substituted, silently linting
    # a different tree than the argument named.
    if raw_paths and raw_paths[0] == "check" and not Path("check").exists():
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
            if args.diff is not None:
                # The rewrite re-analysed every file, so the filter has to be
                # reapplied or the exit code covers pre-existing findings on
                # lines this change never touched.
                all_diagnostics, diff_errors = _filter_to_changed(
                    all_diagnostics, args.diff)
                all_errors.extend(diff_errors)
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
            "end_lineno": d.end_lineno,
            "end_col_offset": d.end_col_offset,
            "rule_id": d.rule_id,
            "rule_name": d.rule_name,
            "message": d.message,
            "fix_suggestion": d.fix_suggestion,
            "severity": d.severity,
            # Whether --fix can act on it, without the caller having to
            # reconstruct that from the edits it cannot see.
            "fixable": bool(d.edits),
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


def _read_source_lines(file_path: str) -> tuple[str, ...] | None:
    """Source lines of ``file_path``, or None when it cannot be read.

    Columns have to be converted against the real line: ast's ``col_offset``
    is a UTF-8 byte offset while SARIF's is UTF-16 units, so the two disagree
    everywhere a non-ASCII character sits before the finding.
    """
    try:
        data = Path(file_path).read_bytes()
    except OSError:
        return None
    try:
        return tuple(data.decode("utf-8-sig").splitlines())
    except UnicodeDecodeError:
        return None


def _utf16_col(line: str, byte_col: int) -> int:
    """1-based SARIF column for a 0-based UTF-8 byte offset into ``line``."""
    prefix = line.encode("utf-8")[:byte_col].decode("utf-8", errors="replace")
    return len(prefix.encode("utf-16-le")) // 2 + 1


def _region(d, sources: dict) -> dict:
    """SARIF region for a finding, in SARIF's own column units."""
    lines = sources.get(d.file_path)

    def column(lineno: int, byte_col: int) -> int:
        if lines is not None and 1 <= lineno <= len(lines):
            return _utf16_col(lines[lineno - 1], byte_col)
        # Unreadable file: a byte offset beats no position at all.
        return byte_col + 1

    end_line = d.end_lineno if d.end_lineno is not None else d.lineno
    end_col = (d.end_col_offset if d.end_col_offset is not None
               else d.col_offset)
    return {
        "startLine": d.lineno,
        "startColumn": column(d.lineno, d.col_offset),
        "endLine": end_line,
        "endColumn": column(end_line, end_col),
    }


def _print_sarif(diagnostics: list) -> None:
    import json

    rules = [
        {
            "id": rule_id,
            "shortDescription": {"text": RULE_SHORT_DESCRIPTIONS[rule_id]},
            "helpUri": f"{_REPO_URL}#readme",
            # Read before any result exists, so it has to be declared even
            # for a rule that found nothing this run.
            "defaultConfiguration": {
                "level": ("error" if RULE_SEVERITIES[rule_id] == "ERROR"
                          else "warning"),
            },
        }
        for rule_id in sorted(KNOWN_RULE_IDS)
    ]
    sources = {path: _read_source_lines(path)
               for path in {d.file_path for d in diagnostics}}
    results = [
        {
            "ruleId": d.rule_id,
            "level": "error" if d.severity == "ERROR" else "warning",
            "message": {"text": d.message},
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {"uri": _sarif_uri(d.file_path)},
                        "region": _region(d, sources),
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
        # escape(): a path or message is data, not markup. Without it a file
        # called `[bold]x.py` is parsed as a tag and never printed.
        console.print(
            f"[{severity_color}][{d.rule_id}] {d.rule_name}[/{severity_color}] "
            f"[bold]{escape(d.file_path)}:{d.lineno}:{d.col_offset}[/bold] "
            f"- {escape(d.message)}"
        )
        console.print(
            f"    [bold yellow]💡 Fix:[/bold yellow] {escape(d.fix_suggestion)}"
        )
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

