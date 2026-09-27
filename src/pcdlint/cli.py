"""CLI entry point for pcdlint."""

import argparse
import sys
from pathlib import Path

from rich.console import Console
from rich.table import Table

from pcdlint.analyzer import analyze_path
from pcdlint import __version__


def main() -> int:
    parser = argparse.ArgumentParser(
        prog="pcdlint",
        description="Static Taint Linter for Prompt-Cache Determinism",
    )
    parser.add_argument("paths", nargs="*", help="File or directory paths to check")
    parser.add_argument(
        "--format", choices=["text", "json"], default="text",
        help="Output format (default: text)",
    )
    parser.add_argument(
        "--fail-on-warn", action="store_true",
        help="Exit with code 1 if any WARNING is found",
    )
    parser.add_argument(
        "--version", action="version", version=f"pcdlint {__version__}",
    )
    args = parser.parse_args()

    if not args.paths:
        parser.print_help()
        return 0

    raw_paths = list(args.paths)
    # Support both `pcdlint check [paths...]` and `pcdlint [paths...]`
    if raw_paths and raw_paths[0] == "check":
        raw_paths = raw_paths[1:]
        if not raw_paths:
            raw_paths = ["."]

    all_diagnostics = []
    for path_str in raw_paths:
        path = Path(path_str)
        diags = analyze_path(path)
        all_diagnostics.extend(diags)

    all_diagnostics.sort(key=lambda d: (d.file_path, d.lineno, d.col_offset))

    if args.format == "json":
        _print_json(all_diagnostics)
    else:
        _print_text(all_diagnostics)

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
        console.print(f"    [dim]Fix:[/dim] {d.fix_suggestion}")
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

