"""Code analyzer that scans Python files and produces diagnostics."""

import ast
import os
from pathlib import Path

from pcdlint import config, disables
from pcdlint.models import Diagnostic
from pcdlint.rules import RuleEngine
from pcdlint.taint import TaintTracker

SKIP_DIRS: set[str] = {
    ".venv", "venv", "env", "node_modules", ".git", "__pycache__", "build",
    "dist", ".tox", ".nox", ".mypy_cache", ".ruff_cache", ".pytest_cache",
    ".eggs", "htmlcov", "site-packages", ".ipynb_checkpoints",
}
# Iterations over the AST. Each pass lets assignment tracking see the function
# summaries resolved by the previous one, so a call chain resolves one link per
# pass regardless of the order the functions were declared in. 16 is a cost
# ceiling, not a correctness bound -- the loop stops as soon as the summaries
# stop changing. Expression statements (list.append, ...) only run on the first
# pass so they are not applied twice.
_MAX_PASSES = 16


def _child_stmts(node: ast.AST) -> list:
    """Statement children of ``node``, in source order."""
    return [child for child in ast.iter_child_nodes(node) if isinstance(child, ast.stmt)]


def _track_tree(tracker: TaintTracker, tree: ast.AST) -> None:
    """Walk statements in execution order, merging sibling control-flow paths.

    Python executes one arm of a branch, never both. Tracking each arm from
    the same snapshot and may-merging the results is what keeps a taint
    recorded on the ``try`` path from being erased by its handler, and what
    lets two arms that bind the same expression be recognised as equal.
    """
    for pass_no in range(_MAX_PASSES):
        _walk_stmts(tracker, _child_stmts(tree), pass_no)
        if not tracker.build_function_returns(tree):
            break


def _walk_stmts(tracker: TaintTracker, stmts: list, pass_no: int) -> None:
    for stmt in stmts:
        if isinstance(stmt, ast.If):
            _track_if(tracker, stmt, pass_no)
        elif isinstance(stmt, ast.Try):
            _track_try(tracker, stmt, pass_no)
        elif isinstance(stmt, (ast.For, ast.AsyncFor, ast.While)):
            _track_loop(tracker, stmt, pass_no)
        else:
            _track_simple(tracker, stmt, pass_no)
            _walk_stmts(tracker, _child_stmts(stmt), pass_no)


def _track_simple(tracker: TaintTracker, stmt: ast.AST, pass_no: int) -> None:
    if isinstance(stmt, (ast.Assign, ast.AnnAssign)):
        tracker.track_assignment(stmt)
    elif isinstance(stmt, ast.Expr):
        # Reaches the tracker on every pass: the idempotent marks inside
        # (a shuffle tainting its argument) have to survive the reassignment
        # a later pass makes, while the in-place list mutations stay gated
        # on pass_no inside the tracker.
        tracker.track_expr_stmt(stmt, pass_no)
    elif pass_no == 0 and isinstance(stmt, ast.AugAssign):
        # Augmented assignments are not idempotent either, so first pass only.
        tracker.track_aug_assign(stmt)


def _track_if(tracker: TaintTracker, node: ast.If, pass_no: int) -> None:
    before = tracker.snapshot()
    _walk_stmts(tracker, node.body, pass_no)
    on_body = tracker.snapshot()
    tracker.restore(before)
    _walk_stmts(tracker, node.orelse, pass_no)
    on_else = tracker.snapshot()
    tracker.restore(on_body)
    tracker.merge_path(on_else)


def _track_try(tracker: TaintTracker, node: ast.Try, pass_no: int) -> None:
    before = tracker.snapshot()
    _walk_stmts(tracker, node.body, pass_no)
    _walk_stmts(tracker, node.orelse, pass_no)
    on_success = tracker.snapshot()
    tracker.restore(before)
    for handler in node.handlers:
        _walk_stmts(tracker, handler.body, pass_no)
    on_failure = tracker.snapshot()
    tracker.restore(on_success)
    tracker.merge_path(on_failure)
    # ``finally`` runs on both paths, so it follows the merge.
    _walk_stmts(tracker, node.finalbody, pass_no)


def _track_loop(tracker: TaintTracker, node: ast.For | ast.AsyncFor | ast.While,
                pass_no: int) -> None:
    before = tracker.snapshot()
    _walk_stmts(tracker, node.body, pass_no)
    on_iteration = tracker.snapshot()
    tracker.restore(before)
    zero_iterations = tracker.snapshot()
    tracker.restore(on_iteration)
    tracker.merge_path(zero_iterations)
    _walk_stmts(tracker, node.orelse, pass_no)


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
    """Read a source file as the bytes on disk, minus any UTF-8 BOM.

    Going through bytes rather than ``Path.read_text`` fixes two silent
    rejections at once: ``utf-8-sig`` drops the leading U+FEFF that
    ``ast.parse`` rejects (editors do save BOM'd files), and no text-mode
    translation means CRLF comes back as CRLF -- ast's ``col_offset`` has to
    describe the bytes that are actually there, and --fix has to write back
    exactly what it did not touch.
    """
    try:
        return path.read_bytes().decode("utf-8-sig"), None
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
