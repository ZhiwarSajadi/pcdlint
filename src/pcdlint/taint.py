"""Static taint and prefix tracking engine for pcdlint."""

import ast
from typing import Dict, List, Optional, Set

from pcdlint.models import TaintOrigin

TAINT_SOURCES: Dict[tuple, str] = {
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
    "PROMPT", "SYSTEM_MESSAGE", "PREFIX", "HEADER", "STATIC_PROMPT",
}


def _extract_dotted_name(node: ast.AST) -> str:
    """Extract dotted identifier name from an AST node (e.g. datetime.now)."""
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        parent = _extract_dotted_name(node.value)
        return f"{parent}.{node.attr}" if parent else node.attr
    return ""


def _is_string_concat(node: ast.AST) -> bool:
    """Check if node is a string concatenation (JoinedStr or BinOp with Add)."""
    return isinstance(node, ast.JoinedStr) or (isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add))


class TaintTracker:
    """Tracks tainted variables and static prefix solids across an AST."""

    def __init__(self) -> None:
        self._tainted_vars: Dict[str, TaintOrigin] = {}
        self._prefix_tainted_vars: Dict[str, TaintOrigin] = {}
        self._set_vars: Set[str] = set()
        self._static_prefix_vars: Dict[str, str] = {}
        self._var_lineno: Dict[str, int] = {}
        self._tools_mutated_vars: Set[str] = set()
        self._json_unsorted_vars: Set[str] = set()
        self._list_vars: Dict[str, ast.List] = {}
        self._dict_vars: Dict[str, ast.Dict] = {}
        self._llm_used_vars: Set[str] = set()

    @property
    def tainted_vars(self) -> Dict[str, TaintOrigin]:
        return self._tainted_vars

    @property
    def prefix_tainted_vars(self) -> Dict[str, TaintOrigin]:
        return self._prefix_tainted_vars

    @property
    def set_vars(self) -> Set[str]:
        return self._set_vars

    @property
    def static_prefix_vars(self) -> Dict[str, str]:
        return self._static_prefix_vars

    def is_taint_source(self, node: ast.Call) -> Optional[TaintOrigin]:
        """Check if an ast.Call is a known non-deterministic taint source."""
        dotted = _extract_dotted_name(node.func)
        if not dotted:
            return None

        # Direct match in TAINT_SOURCES
        for (mod, fn), full in TAINT_SOURCES.items():
            if dotted == f"{mod}.{fn}" or dotted == full:
                return TaintOrigin(variable_name="", source_call=full, lineno=node.lineno)
            if dotted == fn:
                return TaintOrigin(variable_name="", source_call=full, lineno=node.lineno)
            # Support nested module access like datetime.datetime.now
            if dotted.endswith(f".{fn}") and mod in dotted:
                return TaintOrigin(variable_name="", source_call=full, lineno=node.lineno)

        return None

    def is_static_prefix_solid(self, node: ast.AST) -> bool:
        """Check if node is a heavy static content string or static constant variable."""
        if isinstance(node, ast.FormattedValue):
            return self.is_static_prefix_solid(node.value)
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            if len(node.value) >= 200:
                return True
        if isinstance(node, ast.Name):
            if node.id in STATIC_PREFIX_NAMES or node.id in self._static_prefix_vars:
                return True
            if node.id.isupper():
                return True
        return False

    def _flatten_string_expr(self, node: ast.AST) -> List[ast.AST]:
        """Flatten nested BinOp(op=Add) and JoinedStr into an ordered list of part nodes."""
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
            return self._flatten_string_expr(node.left) + self._flatten_string_expr(node.right)
        if isinstance(node, ast.JoinedStr):
            parts: List[ast.AST] = []
            for val in node.values:
                if isinstance(val, ast.FormattedValue):
                    parts.extend(self._flatten_string_expr(val.value))
                else:
                    parts.append(val)
            return parts
        return [node]

    def get_taint_origin_of_node(self, node: ast.AST) -> Optional[TaintOrigin]:
        """Resolve TaintOrigin from an AST node if it contains taint."""
        if isinstance(node, ast.FormattedValue):
            return self.get_taint_origin_of_node(node.value)
        if isinstance(node, ast.Name):
            return self._tainted_vars.get(node.id)
        if isinstance(node, ast.Attribute):
            origin = self.get_taint_origin_of_node(node.value)
            if origin:
                return origin
            return None
        if isinstance(node, ast.Call):
            origin = self.is_taint_source(node)
            if origin:
                return origin
            # Method call on tainted object: e.g. now.isoformat(), datetime.now().strftime(...)
            if isinstance(node.func, ast.Attribute):
                caller_origin = self.get_taint_origin_of_node(node.func.value)
                if caller_origin:
                    return caller_origin
            # Type conversions: str(taint), int(taint), float(taint), repr(taint)
            if isinstance(node.func, ast.Name) and node.func.id in ("str", "int", "float", "repr", "bytes") and node.args:
                return self.get_taint_origin_of_node(node.args[0])
            if self._is_format_call(node):
                return self._find_origin_in_format(node)
            return None
        if _is_string_concat(node):
            parts = self._flatten_string_expr(node)
            for part in parts:
                if part is not node:
                    origin = self.get_taint_origin_of_node(part)
                    if origin:
                        return origin
            return None

    def check_sequence_prefix_taint(self, parts: List[ast.AST]) -> Optional[TaintOrigin]:
        """Determine if a sequence of string parts contains prefix taint.

        Rules:
        - If a tainted expression appears BEFORE a static prefix solid, it is PREFIX_TAINTED.
        - If a static prefix solid appears FIRST and taint only appears AFTER it (with no
          subsequent static solid), it is NOT prefix-tainted (cache prefix is preserved).
        - If there is NO static prefix solid, but a tainted expression appears at index 0 or
          within the first 500 characters of static text, it is PREFIX_TAINTED.
        """
        first_taint_idx = -1
        first_taint_origin: Optional[TaintOrigin] = None
        static_solid_indices: List[int] = []
        static_chars_before_first_taint = 0

        for idx, part in enumerate(parts):
            if self.is_static_prefix_solid(part):
                static_solid_indices.append(idx)
            origin = self.get_taint_origin_of_node(part)
            if origin and first_taint_idx == -1:
                first_taint_idx = idx
                first_taint_origin = origin
            elif first_taint_idx == -1 and isinstance(part, ast.Constant) and isinstance(part.value, str):
                static_chars_before_first_taint += len(part.value)

        if first_taint_idx == -1 or first_taint_origin is None:
            return None

        # Rule 1: Taint appears BEFORE any static solid
        for solid_idx in static_solid_indices:
            if solid_idx > first_taint_idx:
                return first_taint_origin

        # Rule 2: Static solid appears FIRST, taint only appears at end
        if static_solid_indices and all(s_idx < first_taint_idx for s_idx in static_solid_indices):
            return None

        # Rule 3: No static solid, taint within first 500 characters of static text
        if not static_solid_indices:
            if static_chars_before_first_taint < 500:
                return first_taint_origin

        return None

    def track_assignment(self, node: ast.AST) -> None:
        """Analyze an assignment statement (Assign or AnnAssign) and update states."""
        targets: List[str] = []
        value = None
        if isinstance(node, ast.Assign):
            for t in node.targets:
                if isinstance(t, ast.Name):
                    targets.append(t.id)
            value = node.value
        elif isinstance(node, ast.AnnAssign):
            if isinstance(node.target, ast.Name):
                targets.append(node.target.id)
            value = node.value

        if not value or not targets:
            return

        for var_name in targets:
            self._var_lineno[var_name] = node.lineno
            self._track_target_value(var_name, value, node.lineno)

    def _track_target_value(self, var_name: str, value: ast.AST, lineno: int) -> None:
        # 0. Variable alias: e.g. b = a
        if isinstance(value, ast.Name):
            src = value.id
            if src in self._tainted_vars:
                self._tainted_vars[var_name] = self._tainted_vars[src]
            if src in self._prefix_tainted_vars:
                self._prefix_tainted_vars[var_name] = self._prefix_tainted_vars[src]
            if src in self._set_vars:
                self._set_vars.add(var_name)
            if src in self._static_prefix_vars:
                self._static_prefix_vars[var_name] = self._static_prefix_vars[src]
            if src in self._tools_mutated_vars:
                self._tools_mutated_vars.add(var_name)
            if src in self._json_unsorted_vars:
                self._json_unsorted_vars.add(var_name)
            if src in self._list_vars:
                self._list_vars[var_name] = self._list_vars[src]
            if src in self._dict_vars:
                self._dict_vars[var_name] = self._dict_vars[src]
            return

        # 1. Dict expressions
        if isinstance(value, ast.Dict):
            self._dict_vars[var_name] = value

        # 2. List expressions
        if isinstance(value, ast.List):
            self._list_vars[var_name] = value

        # 3. Set expressions
        if isinstance(value, (ast.Set, ast.SetComp)):
            self._set_vars.add(var_name)
            if var_name == "tools":
                self._tools_mutated_vars.add(var_name)
            return

        # 4. Calls
        if isinstance(value, ast.Call):
            if self._is_set_call(value):
                self._set_vars.add(var_name)
                if var_name == "tools":
                    self._tools_mutated_vars.add(var_name)
                return

            if self._is_shuffle_call(value):
                self._tools_mutated_vars.add(var_name)
                return

            # Check if list constructed from set: list(my_set)
            if isinstance(value.func, ast.Name) and value.func.id == "list" and value.args:
                arg = value.args[0]
                if (isinstance(arg, ast.Name) and self.is_set_variable(arg.id)) or isinstance(arg, (ast.Set, ast.SetComp)):
                    self._tools_mutated_vars.add(var_name)

            if self._is_json_dumps(value):
                has_sort = any(
                    kw.arg == "sort_keys" and isinstance(kw.value, ast.Constant)
                    and kw.value.value is True
                    for kw in value.keywords
                )
                if not has_sort:
                    self._json_unsorted_vars.add(var_name)

            if self._is_file_read(value):
                if var_name.isupper():
                    self._static_prefix_vars[var_name] = "file_read"
                return

        # 5. List comprehension iterating over set: [t for t in tool_set]
        if isinstance(value, ast.ListComp):
            for gen in value.generators:
                if (isinstance(gen.iter, ast.Name) and self.is_set_variable(gen.iter.id)) or isinstance(gen.iter, (ast.Set, ast.SetComp)):
                    self._tools_mutated_vars.add(var_name)

        # 6. String constant assigned to UPPER_CASE variable
        if isinstance(value, ast.Constant) and isinstance(value.value, str):
            if var_name.isupper():
                self._static_prefix_vars[var_name] = value.value
            return

        # 7. JoinedStr (f-string) and BinOp (+) string concatenation
        if _is_string_concat(value):
            parts = self._flatten_string_expr(value)
            origin = self.check_sequence_prefix_taint(parts)
            if origin:
                self._tainted_vars[var_name] = origin
                self._prefix_tainted_vars[var_name] = origin
            else:
                for part in parts:
                    if part is not value:
                        p_orig = self.get_taint_origin_of_node(part)
                        if p_orig:
                            self._tainted_vars[var_name] = p_orig
                            break
            return

        # 8. Format call: "...".format(...)
        if isinstance(value, ast.Call) and self._is_format_call(value):
            parts = list(value.args) + [kw.value for kw in value.keywords if kw.value]
            origin = self.check_sequence_prefix_taint(parts) if parts else None
            if origin:
                self._tainted_vars[var_name] = origin
                self._prefix_tainted_vars[var_name] = origin
            else:
                any_orig = self._find_origin_in_format(value)
                if any_orig:
                    self._tainted_vars[var_name] = any_orig
            return

        # 9. General taint origin
        origin = self.get_taint_origin_of_node(value)
        if origin:
            self._tainted_vars[var_name] = origin
            self._prefix_tainted_vars[var_name] = origin

    def track_aug_assign(self, node: ast.AugAssign) -> None:
        """Track augmented assignments like messages += [...] or tools += [...]."""
        if isinstance(node.target, ast.Name):
            var_name = node.target.id
            if var_name in self._list_vars and isinstance(node.value, ast.List):
                self._list_vars[var_name].elts.extend(node.value.elts)
            if var_name == "tools":
                self._tools_mutated_vars.add(var_name)
            if _is_string_concat(node.value):
                parts = self._flatten_string_expr(node.value)
                origin = self.check_sequence_prefix_taint(parts)
                if origin:
                    self._tainted_vars[var_name] = origin
                    self._prefix_tainted_vars[var_name] = origin

    def track_expr_stmt(self, node: ast.Expr) -> None:
        """Track standalone expressions such as random.shuffle(tools) or list.append()."""
        if isinstance(node.value, ast.Call):
            if self._is_shuffle_call(node.value):
                if node.value.args and isinstance(node.value.args[0], ast.Name):
                    self._tools_mutated_vars.add(node.value.args[0].id)
            if isinstance(node.value.func, ast.Attribute):
                attr = node.value.func.attr
                caller = node.value.func.value
                if isinstance(caller, ast.Name):
                    if attr == "append" and node.value.args:
                        if caller.id in self._list_vars:
                            self._list_vars[caller.id].elts.append(node.value.args[0])
                    elif attr == "extend" and node.value.args:
                        arg = node.value.args[0]
                        if caller.id in self._list_vars and isinstance(arg, ast.List):
                            self._list_vars[caller.id].elts.extend(arg.elts)
                        if isinstance(arg, ast.Name) and self.is_set_variable(arg.id):
                            self._tools_mutated_vars.add(caller.id)

    def _is_format_call(self, node: ast.Call) -> bool:
        return isinstance(node.func, ast.Attribute) and node.func.attr == "format"

    def _find_origin_in_format(self, node: ast.Call) -> Optional[TaintOrigin]:
        for arg in node.args:
            origin = self.get_taint_origin_of_node(arg)
            if origin:
                return origin
        for kw in node.keywords:
            if kw.value:
                origin = self.get_taint_origin_of_node(kw.value)
                if origin:
                    return origin
        return None

    def _is_set_call(self, node: ast.Call) -> bool:
        return isinstance(node.func, ast.Name) and node.func.id == "set"

    def _is_shuffle_call(self, node: ast.Call) -> bool:
        dotted = _extract_dotted_name(node.func)
        return dotted in ("random.shuffle", "shuffle")

    def _is_file_read(self, node: ast.Call) -> bool:
        return isinstance(node.func, ast.Attribute) and node.func.attr in ("read", "read_text")

    def _is_json_dumps(self, node: ast.Call) -> bool:
        dotted = _extract_dotted_name(node.func)
        return dotted in ("json.dumps", "dumps")

    def get_prefix_tainted(self, node: ast.AST) -> Optional[TaintOrigin]:
        """Check if an AST expression is prefix-tainted and return its TaintOrigin."""
        if isinstance(node, ast.Name):
            return self._prefix_tainted_vars.get(node.id)
        if _is_string_concat(node):
            parts = self._flatten_string_expr(node)
            return self.check_sequence_prefix_taint(parts)
        if isinstance(node, ast.Call):
            origin = self.is_taint_source(node)
            if origin:
                return origin
            if isinstance(node.func, ast.Attribute):
                caller_origin = self.get_taint_origin_of_node(node.func.value)
                if caller_origin:
                    return caller_origin
            if isinstance(node.func, ast.Name) and node.func.id in ("str", "int", "float", "repr", "bytes") and node.args:
                return self.get_taint_origin_of_node(node.args[0])
            if self._is_format_call(node):
                return self._find_origin_in_format(node)
        return None

    def is_tainted_variable(self, var_name: str) -> bool:
        return var_name in self._tainted_vars

    def is_set_variable(self, var_name: str) -> bool:
        return var_name in self._set_vars

    def is_tools_mutated(self, var_name: str) -> bool:
        return var_name in self._tools_mutated_vars

    def is_json_unsorted(self, var_name: str) -> bool:
        return var_name in self._json_unsorted_vars

