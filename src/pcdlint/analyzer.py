"""Code analyzer that scans Python files and produces diagnostics."""

import ast
import os
from pathlib import Path
from typing import List, Set

from pcdlint.models import Diagnostic
from pcdlint.taint import TaintTracker
from pcdlint.rules import RuleEngine

SKIP_DIRS: Set[str] = {".venv", "venv", "node_modules", ".git", "__pycache__", "build", "dist"}


def _run_engine(tracker: TaintTracker, tree: ast.AST, file_path: str) -> List[Diagnostic]:
    engine = RuleEngine(tracker)
    engine._file_path = file_path
    engine.prepare(tree)
    for node in ast.walk(tree):
        engine.check_node(node)
    return engine._diagnostics


def _find_if_mutations(tree: ast.AST, tracker: TaintTracker) -> None:
    """Find variables mutated inside if/else branches (e.g. tools.append(...) inside ast.If)."""
    for node in ast.walk(tree):
        if isinstance(node, ast.If):
            for stmt in node.body + node.orelse:
                for sub in ast.walk(stmt):
                    if isinstance(sub, ast.Call) and isinstance(sub.func, ast.Attribute):
                        if sub.func.attr in ("append", "extend", "insert") and isinstance(sub.func.value, ast.Name):
                            tracker._tools_mutated_vars.add(sub.func.value.id)
                    elif isinstance(sub, ast.AugAssign) and isinstance(sub.target, ast.Name):
                        tracker._tools_mutated_vars.add(sub.target.id)
                    elif isinstance(sub, ast.Assign):
                        for t in sub.targets:
                            if isinstance(t, ast.Name) and t.id == "tools":
                                tracker._tools_mutated_vars.add(t.id)
                    elif isinstance(sub, ast.AnnAssign) and isinstance(sub.target, ast.Name) and sub.target.id == "tools":
                        tracker._tools_mutated_vars.add(sub.target.id)


def analyze_code(source_code: str, file_path: str = "") -> List[Diagnostic]:
    try:
        tree = ast.parse(source_code, filename=file_path)
    except SyntaxError:
        return []

    tracker = TaintTracker()
    _find_if_mutations(tree, tracker)
    for node in ast.walk(tree):
        if isinstance(node, (ast.Assign, ast.AnnAssign)):
            tracker.track_assignment(node)
        elif isinstance(node, ast.AugAssign):
            tracker.track_aug_assign(node)
        elif isinstance(node, ast.Expr):
            tracker.track_expr_stmt(node)

    diagnostics = _run_engine(tracker, tree, file_path)

    seen = set()
    unique: List[Diagnostic] = []
    for d in diagnostics:
        key = (d.lineno, d.col_offset, d.rule_id)
        if key not in seen:
            seen.add(key)
            unique.append(d)
    return unique


def analyze_path(target_path: Path) -> List[Diagnostic]:
    all_diagnostics: List[Diagnostic] = []

    if target_path.is_file() and target_path.suffix == ".py":
        source = target_path.read_text(encoding="utf-8")
        diags = analyze_code(source, str(target_path))
        all_diagnostics.extend(diags)
    elif target_path.is_dir():
        for root, dirs, files in os.walk(str(target_path)):
            dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
            for fname in files:
                if fname.endswith(".py"):
                    fpath = Path(root) / fname
                    try:
                        source = fpath.read_text(encoding="utf-8")
                        diags = analyze_code(source, str(fpath))
                        all_diagnostics.extend(diags)
                    except (OSError, UnicodeDecodeError):
                        continue
    return all_diagnostics

