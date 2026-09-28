"""Code analyzer that scans Python files and produces diagnostics."""

import ast
import os
from pathlib import Path

from pcdlint import config, disables
from pcdlint.models import Diagnostic
from pcdlint.rules import RuleEngine
from pcdlint.taint import TaintTracker

SKIP_DIRS: set[str] = {
    ".venv", "venv", "node_modules", ".git", "__pycache__", "build", "dist",
    ".tox", ".nox", ".mypy_cache", ".ruff_cache", ".eggs", "htmlcov",
}
# Passes over the AST: later passes let assignment tracking see function-return
# taint resolved by the previous pass. Expression statements (list.append, ...)
# only run on the first pass so they are not applied twice.
_MAX_PASSES = 3


def _walk_source_order(tree: ast.AST):
    """Depth-first pre-order walk, i.e. the order Python actually executes code.

    ``ast.walk`` is breadth-first, which would apply a statement nested in an
    ``if`` body after every later top-level statement.
    """
    stack = [tree]
    while stack:
        node = stack.pop()
        yield node
        stack.extend(reversed(list(ast.iter_child_nodes(node))))


def _track_tree(tracker: TaintTracker, tree: ast.AST) -> None:
    for pass_no in range(_MAX_PASSES):
        for node in _walk_source_order(tree):
            if isinstance(node, (ast.Assign, ast.AnnAssign)):
                tracker.track_assignment(node)
            elif pass_no == 0:
                if isinstance(node, ast.AugAssign):
                    tracker.track_aug_assign(node)
                elif isinstance(node, ast.Expr):
                    tracker.track_expr_stmt(node)
        if not tracker.build_function_returns(tree):
            break


def _dedupe(diagnostics: list[Diagnostic]) -> list[Diagnostic]:
    seen = set()
    unique: list[Diagnostic] = []
    for d in diagnostics:
        key = (d.lineno, d.col_offset, d.rule_id)
        if key not in seen:
            seen.add(key)
            unique.append(d)
    return unique


def analyze_code_ex(source_code: str, file_path: str = "", *,
                    select: frozenset | None = None,
                    ignore: frozenset | None = None) -> tuple[list[Diagnostic], str | None]:
    """Analyze source text, also reporting why it could not be analyzed.

    Returns ``(diagnostics, error)`` where ``error`` is None when parsing succeeded.

    ``select``/``ignore`` are caller-supplied rule sets (the CLI's
    ``--select``/``--ignore``). When either is None the value comes from the
    nearest ``[tool.pcdlint]`` instead, so the flags override config per option.
    """
    try:
        tree = ast.parse(source_code, filename=file_path)
    except SyntaxError as exc:
        where = file_path or "<source>"
        line = f"line {exc.lineno}" if exc.lineno else "unknown line"
        return [], f"cannot parse {where}: {exc.msg} ({line})"

    try:
        cfg = config.load_for(file_path)
    except config.ConfigError as exc:
        return [], str(exc)

    tracker = TaintTracker()
    tracker.build_scopes(tree)
    _track_tree(tracker, tree)

    engine = RuleEngine(tracker)
    found = engine.run(tree, file_path)

    # Single suppression point: rules never see disable comments or config.
    off = disables.parse(source_code)
    keep_select = select if select is not None else cfg.select
    keep_ignore = ignore if ignore is not None else cfg.ignore
    kept = [
        d for d in found
        if not off.disabled(d.lineno, d.rule_id)
        and config.selected(d.rule_id, keep_select, keep_ignore)
    ]
    return _dedupe(kept), None


def analyze_code(source_code: str, file_path: str = "") -> list[Diagnostic]:
    """Analyze source text; unparseable source yields no diagnostics."""
    diagnostics, _error = analyze_code_ex(source_code, file_path)
    return diagnostics


def _read_source(path: Path) -> tuple[str | None, str | None]:
    try:
        return path.read_text(encoding="utf-8"), None
    except UnicodeDecodeError as exc:
        return None, f"cannot decode {path} as UTF-8: {exc}"
    except OSError as exc:
        return None, f"cannot read {path}: {exc}"


def analyze_path_ex(target_path: Path, *,
                    select: frozenset | None = None,
                    ignore: frozenset | None = None) -> tuple[list[Diagnostic], list[str]]:
    """Analyze a file or directory, returning diagnostics and blocking errors.

    Every path that cannot be analyzed (missing, not Python, undecodable,
    unparseable) is reported instead of silently treated as clean.
    """
    errors: list[str] = []

    if target_path.is_file():
        if target_path.suffix != ".py":
            return [], [f"not a Python file: {target_path}"]
        source, error = _read_source(target_path)
        if error:
            return [], [error]
        diagnostics, error = analyze_code_ex(source or "", str(target_path),
                                             select=select, ignore=ignore)
        if error:
            errors.append(error)
        return diagnostics, errors

    if not target_path.exists():
        return [], [f"path does not exist: {target_path}"]
    if not target_path.is_dir():
        return [], [f"not a file or directory: {target_path}"]

    all_diagnostics: list[Diagnostic] = []
    for root, dirs, files in os.walk(str(target_path)):
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
        for fname in files:
            if not fname.endswith(".py"):
                continue
            fpath = Path(root) / fname
            source, error = _read_source(fpath)
            if error:
                errors.append(error)
                continue
            diagnostics, error = analyze_code_ex(source or "", str(fpath),
                                                 select=select, ignore=ignore)
            if error:
                errors.append(error)
                continue
            all_diagnostics.extend(diagnostics)
    return all_diagnostics, errors


def analyze_path(target_path: Path, *,
                 select: frozenset | None = None,
                 ignore: frozenset | None = None) -> list[Diagnostic]:
    """Analyze a file or directory and return its diagnostics only."""
    diagnostics, _errors = analyze_path_ex(target_path, select=select, ignore=ignore)
    return diagnostics
