"""Static taint and prefix tracking engine for pcdlint."""

import ast
from typing import Dict, Optional, Set

from pcdlint.models import TaintOrigin

TAINT_SOURCES: Dict[str, str] = {
    ("datetime", "now"): "datetime.now",
    ("datetime", "utcnow"): "datetime.utcnow",
    ("date", "today"): "date.today",
    ("time", "time"): "time.time",
    ("time", "monotonic"): "time.monotonic",
    ("time", "perf_counter"): "time.perf_counter",
    ("uuid", "uuid4"): "uuid.uuid4",
    ("uuid", "uuid1"): "uuid.uuid1",
    ("random", "random"): "random.random",
    ("random", "randint"): "random.randint",
    ("random", "choice"): "random.choice",
    ("random", "randrange"): "random.randrange",
    ("secrets", "token_hex"): "secrets.token_hex",
    ("secrets", "token_urlsafe"): "secrets.token_urlsafe",
    ("os", "urandom"): "os.urandom",
}

STATIC_PREFIX_NAMES: Set[str] = {
    "SYSTEM_PROMPT", "KNOWLEDGE_BASE", "STATIC_RULES",
    "PROMPT", "SYSTEM_MESSAGE", "PREFIX", "HEADER",
}


class TaintTracker:
    """Tracks tainted variables and static prefix solids across an AST."""

    def __init__(self) -> None:
        self._tainted_vars: Dict[str, TaintOrigin] = {}
        self._set_vars: Set[str] = set()
        self._static_prefix_vars: Dict[str, str] = {}
        self._var_lineno: Dict[str, int] = {}
        self._shuffled_vars: Set[str] = set()
        self._json_unsorted_vars: Set[str] = set()

    @property
    def tainted_vars(self) -> Dict[str, TaintOrigin]:
        return self._tainted_vars

    @property
    def set_vars(self) -> Set[str]:
        return self._set_vars

    @property
    def static_prefix_vars(self) -> Dict[str, str]:
        return self._static_prefix_vars

    def is_taint_source(self, node: ast.Call) -> Optional[TaintOrigin]:
        func = node.func
        if isinstance(func, ast.Attribute):
            if isinstance(func.value, ast.Name):
                key = (func.value.id, func.attr)
                if key in TAINT_SOURCES:
                    return TaintOrigin(
                        variable_name="",
                        source_call=TAINT_SOURCES[key],
                        lineno=node.lineno,
                    )
        elif isinstance(func, ast.Name):
            for (mod, fn), full in TAINT_SOURCES.items():
                if fn == func.id:
                    return TaintOrigin(
                        variable_name="",
                        source_call=full,
                        lineno=node.lineno,
                    )
        return None

    def is_static_prefix_solid(self, node: ast.AST) -> bool:
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            if len(node.value) >= 200:
                return True
        if isinstance(node, ast.Name) and node.id.isupper():
            if node.id in self._static_prefix_vars or node.id in STATIC_PREFIX_NAMES:
                return True
        return False

    def _is_static_solid(self, node: ast.AST) -> bool:
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            if len(node.value) >= 200:
                return True
        if isinstance(node, ast.Name) and node.id.isupper():
            if node.id in self._static_prefix_vars or node.id in STATIC_PREFIX_NAMES:
                return True
        return False

    def _is_tainted_expr(self, node: ast.AST) -> bool:
        if isinstance(node, ast.Name):
            return node.id in self._tainted_vars
        if isinstance(node, ast.Call):
            return self.is_taint_source(node) is not None
        if isinstance(node, ast.JoinedStr):
            return self._check_joinedstr_taint(node)
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
            return self._check_binop_taint(node)
        return False

    def _check_joinedstr_taint(self, node: ast.JoinedStr) -> bool:
        """True if a tainted expr appears before a static prefix solid in the f-string.

        A tainted expression at position 0 (before any static content) is prefix-tainted.
        A tainted expression after a static prefix solid is NOT prefix-tainted.
        """
        has_static_solid_before = False
        for part in node.values:
            if isinstance(part, ast.Constant) and isinstance(part.value, str):
                if self._is_static_solid(part):
                    has_static_solid_before = True
            elif isinstance(part, ast.FormattedValue):
                if self._is_tainted_expr(part.value):
                    if has_static_solid_before:
                        return False
                    return True
                if isinstance(part.value, ast.Name) and self._is_static_solid(part.value):
                    has_static_solid_before = True
        return False

    def _check_binop_taint(self, node: ast.BinOp) -> bool:
        left_tainted = self._is_tainted_expr(node.left)
        right_static = self._is_static_solid(node.right)
        if left_tainted and right_static:
            return True
        if left_tainted and not self._is_static_solid(node.right):
            return True
        return False

    def track_assignment(self, node: ast.Assign) -> None:
        if not node.value:
            return
        for target in node.targets:
            if not isinstance(target, ast.Name):
                continue
            var_name = target.id
            self._var_lineno[var_name] = node.lineno

            if isinstance(node.value, ast.Call):
                origin = self.is_taint_source(node.value)
                if origin:
                    self._tainted_vars[var_name] = origin
                    continue
                if self._is_set_call(node.value):
                    self._set_vars.add(var_name)
                    continue
                if self._is_shuffle_call(node.value):
                    self._shuffled_vars.add(var_name)
                    continue
                if self._is_json_dumps(node.value):
                    has_sort = any(
                        kw.arg == "sort_keys" and isinstance(kw.value, ast.Constant)
                        and kw.value.value is True
                        for kw in node.value.keywords
                    )
                    if not has_sort:
                        self._json_unsorted_vars.add(var_name)
                    continue

            if isinstance(node.value, ast.Set):
                self._set_vars.add(var_name)
                continue
            if isinstance(node.value, ast.SetComp):
                self._set_vars.add(var_name)
                continue
            if self._is_file_read(node.value):
                if var_name.isupper():
                    self._static_prefix_vars[var_name] = "file_read"
                continue
            if isinstance(node.value, ast.JoinedStr):
                if self._check_joinedstr_taint(node.value):
                    origin = self._find_origin_in_joinedstr(node.value)
                    if origin:
                        self._tainted_vars[var_name] = origin
                continue
            if isinstance(node.value, ast.BinOp) and isinstance(node.value.op, ast.Add):
                if self._check_binop_taint(node.value):
                    origin = self._find_origin_in_binop(node.value)
                    if origin:
                        self._tainted_vars[var_name] = origin
                continue
            if isinstance(node.value, ast.Call):
                if self._is_format_call(node.value):
                    if self._check_format_taint(node.value):
                        origin = self._find_origin_in_format(node.value)
                        if origin:
                            self._tainted_vars[var_name] = origin
                continue

    def track_expr_stmt(self, node: ast.Expr) -> None:
        if isinstance(node.value, ast.Call):
            if self._is_shuffle_call(node.value):
                if node.value.args and isinstance(node.value.args[0], ast.Name):
                    self._shuffled_vars.add(node.value.args[0].id)

    def _is_format_call(self, node: ast.Call) -> bool:
        return isinstance(node.func, ast.Attribute) and node.func.attr == "format"

    def _check_format_taint(self, node: ast.Call) -> bool:
        for arg in node.args:
            if self._is_tainted_expr(arg):
                return True
        for kw in node.keywords:
            if kw.value and self._is_tainted_expr(kw.value):
                return True
        return False

    def _find_origin_in_format(self, node: ast.Call) -> Optional[TaintOrigin]:
        for arg in node.args:
            if isinstance(arg, ast.Name) and arg.id in self._tainted_vars:
                return self._tainted_vars[arg.id]
            if isinstance(arg, ast.Call):
                origin = self.is_taint_source(arg)
                if origin:
                    return origin
        for kw in node.keywords:
            if kw.value:
                if isinstance(kw.value, ast.Name) and kw.value.id in self._tainted_vars:
                    return self._tainted_vars[kw.value.id]
                if isinstance(kw.value, ast.Call):
                    origin = self.is_taint_source(kw.value)
                    if origin:
                        return origin
        return None

    def _is_set_call(self, node: ast.Call) -> bool:
        return isinstance(node.func, ast.Name) and node.func.id == "set"

    def _is_shuffle_call(self, node: ast.Call) -> bool:
        return (isinstance(node.func, ast.Attribute) and node.func.attr == "shuffle"
                and isinstance(node.func.value, ast.Name) and node.func.value.id == "random")

    def _is_file_read(self, node: ast.Call) -> bool:
        return isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr in ("read", "read_text")

    def _is_json_dumps(self, node: ast.Call) -> bool:
        return isinstance(node.func, ast.Attribute) and isinstance(node.func.value, ast.Name) and node.func.value.id == "json" and node.func.attr == "dumps"

    def _find_origin_in_joinedstr(self, node: ast.JoinedStr) -> Optional[TaintOrigin]:
        for part in node.values:
            if isinstance(part, ast.FormattedValue):
                if isinstance(part.value, ast.Name) and part.value.id in self._tainted_vars:
                    return self._tainted_vars[part.value.id]
                if isinstance(part.value, ast.Call):
                    origin = self.is_taint_source(part.value)
                    if origin:
                        return origin
        return None

    def _find_origin_in_binop(self, node: ast.BinOp) -> Optional[TaintOrigin]:
        if isinstance(node.left, ast.Name) and node.left.id in self._tainted_vars:
            return self._tainted_vars[node.left.id]
        if isinstance(node.right, ast.Name) and node.right.id in self._tainted_vars:
            return self._tainted_vars[node.right.id]
        if isinstance(node.left, ast.Call):
            origin = self.is_taint_source(node.left)
            if origin:
                return origin
        return None

    def get_prefix_tainted(self, node: ast.AST) -> Optional[TaintOrigin]:
        if isinstance(node, ast.Name):
            if node.id in self._tainted_vars:
                return self._tainted_vars[node.id]
            return None
        if isinstance(node, ast.JoinedStr):
            if self._check_joinedstr_taint(node):
                return self._find_origin_in_joinedstr(node)
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
            if self._check_binop_taint(node):
                return self._find_origin_in_binop(node)
        if isinstance(node, ast.Call):
            origin = self.is_taint_source(node)
            if origin:
                return origin
        return None

    def is_tainted_variable(self, var_name: str) -> bool:
        return var_name in self._tainted_vars

    def is_set_variable(self, var_name: str) -> bool:
        return var_name in self._set_vars

    def is_shuffled_variable(self, var_name: str) -> bool:
        return var_name in self._shuffled_vars

    def is_json_unsorted(self, var_name: str) -> bool:
        return var_name in self._json_unsorted_vars

    def is_str_set_operation(self, node: ast.AST) -> bool:
        if isinstance(node, ast.Call):
            if isinstance(node.func, ast.Name) and node.func.id == "str":
                if node.args and isinstance(node.args[0], ast.Name) and self.is_set_variable(node.args[0].id):
                    return True
            if isinstance(node.func, ast.Attribute) and node.func.attr == "join":
                if node.args and isinstance(node.args[0], ast.Name) and self.is_set_variable(node.args[0].id):
                    return True
        if isinstance(node, ast.JoinedStr):
            for part in node.values:
                if isinstance(part, ast.FormattedValue) and isinstance(part.value, ast.Name):
                    if self.is_set_variable(part.value.id):
                        return True
        return False

    def is_sorted_wrap(self, node: ast.AST) -> bool:
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "sorted":
            if node.args and isinstance(node.args[0], ast.Name) and self.is_set_variable(node.args[0].id):
                return True
        if isinstance(node, ast.Call):
            for arg in node.args:
                if self.is_sorted_wrap(arg):
                    return True
            for kw in node.keywords:
                if kw.value and self.is_sorted_wrap(kw.value):
                    return True
        return False
