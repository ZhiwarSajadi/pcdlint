"""Code analyzer that scans Python files and produces diagnostics."""

import ast
from pathlib import Path
from typing import List, Set

from pcdlint.models import Diagnostic
from pcdlint.taint import TaintTracker
from pcdlint.rules import RuleEngine

SKIP_DIRS: Set[str] = {".venv", "venv", "node_modules", ".git", "__pycache__", "build", "dist"}


def _run_engine(tracker: TaintTracker, tree: ast.AST, file_path: str) -> List[Diagnostic]:
    engine = RuleEngine(tracker)
    engine._file_path = file_path
    for node in ast.walk(tree):
        engine.check_node(node)
    return engine._diagnostics


def _find_shuffled_vars(tree: ast.AST, tracker: TaintTracker) -> None:
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name):
                    var_name = target.id
                    if isinstance(node.value, ast.Call):
                        if (isinstance(node.value.func, ast.Attribute) and node.value.func.attr == "shuffle"
                                and isinstance(node.value.func.value, ast.Name) and node.value.func.value.id == "random"):
                            tracker._shuffled_vars.add(var_name)


def analyze_code(source_code: str, file_path: str = "") -> List[Diagnostic]:
    try:
        tree = ast.parse(source_code, filename=file_path)
    except SyntaxError:
        return []

    tracker = TaintTracker()
    _find_shuffled_vars(tree, tracker)
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign):
            tracker.track_assignment(node)
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
        source = target_path.read_text()
        diags = analyze_code(source, str(target_path))
        all_diagnostics.extend(diags)
    elif target_path.is_dir():
        for root, dirs, files in Path(target_path).walk():
            dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
            for fname in files:
                if fname.endswith(".py"):
                    fpath = root / fname
                    try:
                        source = fpath.read_text()
                        diags = analyze_code(source, str(fpath))
                        all_diagnostics.extend(diags)
                    except (OSError, UnicodeDecodeError):
                        continue
    return all_diagnostics


def _is_file_read(node: ast.Call) -> bool:
    if isinstance(node, ast.Call):
        if isinstance(node.func, ast.Attribute):
            if node.func.attr in ("read", "read_text"):
                return True
    return False
