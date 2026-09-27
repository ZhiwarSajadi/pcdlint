"""Static taint and prefix tracking engine for pcdlint."""

import ast
from dataclasses import replace
from typing import Dict, Iterator, List, Optional, Set, Tuple

from pcdlint.models import TaintOrigin

# A lexical scope path, e.g. ("module",) or ("module", "handler", "inner").
Scope = Tuple[str, ...]
MODULE_SCOPE: Scope = ("module",)
# Scope-qualified binding key.
Key = Tuple[Scope, str]

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

# A literal this long is treated as a cache-safe static prefix solid.
STATIC_SOLID_MIN_CHARS = 200
# Bound for repeated-string length math ("x" * huge) so evaluation stays cheap.
_MAX_STATIC_CHARS = 1_000_000
# Passes used to propagate function-return taint into callers.
_MAX_FLOW_PASSES = 3


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


def _static_str_len(node: ast.AST) -> Optional[int]:
    """Length of a statically evaluable string expression, or None.

    Handles string constants plus concatenation and repetition
    (``"rules " * 30``), a common way to build long static prefixes.
    """
    if isinstance(node, ast.Constant):
        return len(node.value) if isinstance(node.value, str) else None
    if isinstance(node, ast.BinOp):
        if isinstance(node.op, ast.Add):
            left = _static_str_len(node.left)
            right = _static_str_len(node.right)
            if left is None or right is None:
                return None
            return min(left + right, _MAX_STATIC_CHARS)
        if isinstance(node.op, ast.Mult):
            for base, count in ((node.left, node.right), (node.right, node.left)):
                if isinstance(count, ast.Constant) and isinstance(count.value, int) \
                        and not isinstance(count.value, bool):
                    length = _static_str_len(base)
                    if length is not None:
                        return max(min(length * count.value, _MAX_STATIC_CHARS), 0)
            return None
    return None


def _has_sort_keys(node: ast.Call) -> bool:
    """True when a json.dumps call passes the literal ``sort_keys=True``."""
    for kw in node.keywords:
        if kw.arg == "sort_keys" and isinstance(kw.value, ast.Constant) and kw.value.value is True:
            return True
    return False


def _child_branch_flags(node: ast.AST, in_branch: bool, count: int) -> List[bool]:
    """Whether each child of ``node`` only executes on some control-flow paths."""
    if isinstance(node, ast.If):
        # test runs unconditionally; body/orelse do not.
        return [in_branch] + [True] * (count - 1)
    if isinstance(node, ast.While):
        return [in_branch] + [True] * (count - 1)
    if isinstance(node, (ast.For, ast.AsyncFor)):
        # target and iter run unconditionally; body/orelse do not.
        return [in_branch, in_branch] + [True] * (count - 2)
    if isinstance(node, (ast.Try, ast.ExceptHandler, ast.IfExp)):
        return [True] * count
    return [in_branch] * count


class _Bindings:
    """Scope-keyed binding tables produced by one tracking pass."""

    __slots__ = (
        "tainted", "prefix_tainted", "sets", "static", "tools_mutated",
        "branch", "json_unsorted", "json_flows", "lists", "dicts",
    )

    def __init__(self) -> None:
        self.tainted: Dict[Key, TaintOrigin] = {}
        self.prefix_tainted: Dict[Key, TaintOrigin] = {}
        self.sets: Set[Key] = set()
        self.static: Dict[Key, str] = {}
        self.tools_mutated: Set[Key] = set()
        self.branch: Set[Key] = set()
        self.json_unsorted: Set[Key] = set()
        self.json_flows: Dict[Key, Set[int]] = {}
        self.lists: Dict[Key, ast.List] = {}
        self.dicts: Dict[Key, ast.Dict] = {}

    def merge(self, other: "_Bindings") -> None:
        self.tainted.update(other.tainted)
        self.prefix_tainted.update(other.prefix_tainted)
        self.sets.update(other.sets)
        self.static.update(other.static)
        self.tools_mutated.update(other.tools_mutated)
        self.branch.update(other.branch)
        self.json_unsorted.update(other.json_unsorted)
        for key, flows in other.json_flows.items():
            self.json_flows.setdefault(key, set()).update(flows)
        self.lists.update(other.lists)
        self.dicts.update(other.dicts)

    def clear_key(self, key: Key) -> None:
        """Drop every binding for one name (strong update on reassignment)."""
        for store in (self.tainted, self.prefix_tainted, self.static,
                      self.json_flows, self.lists, self.dicts):
            store.pop(key, None)
        for store in (self.sets, self.tools_mutated, self.branch, self.json_unsorted):
            store.discard(key)


class TaintTracker:
    """Tracks tainted variables and static prefix solids across an AST."""

    def __init__(self) -> None:
        self._node_scope: Dict[int, Scope] = {}
        self._node_branch: Dict[int, bool] = {}
        self._b = _Bindings()
        self._func_returns: Dict[Key, TaintOrigin] = {}

    # ------------------------------------------------------------------
    # Scopes and branch positions
    # ------------------------------------------------------------------

    def build_scopes(self, tree: ast.AST) -> None:
        """Map every node to its lexical scope and whether it sits in a branch."""
        stack: List[Tuple[ast.AST, Scope, bool]] = [(tree, MODULE_SCOPE, False)]
        while stack:
            node, scope, in_branch = stack.pop()
            self._node_scope[id(node)] = scope
            self._node_branch[id(node)] = in_branch
            child_scope = scope
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                child_scope = scope + (node.name,)
            children = list(ast.iter_child_nodes(node))
            flags = _child_branch_flags(node, in_branch, len(children))
            for child, child_branch in zip(children, flags):
                stack.append((child, child_scope, child_branch))

    def scope_of(self, node: ast.AST) -> Scope:
        """Lexical scope of a node (module scope when unknown)."""
        return self._node_scope.get(id(node), MODULE_SCOPE)

    def in_branch(self, node: ast.AST) -> bool:
        """True when the node only runs on some paths (if/loop/try body)."""
        return self._node_branch.get(id(node), False)

    def _candidates(self, store: object, name: str,
                    node: Optional[ast.AST], scope: Optional[Scope]) -> Iterator[Key]:
        """Keys to try for ``name``, innermost scope first."""
        if scope is None:
            scope = self.scope_of(node) if node is not None else None
        if scope is None:
            # Legacy bare-name lookup: module scope, then any other scope.
            yield (MODULE_SCOPE, name)
            for key in store:  # type: ignore[union-attr]
                if key[1] == name and key != (MODULE_SCOPE, name):
                    yield key
            return
        for i in range(len(scope), 0, -1):
            yield (scope[:i], name)

    def _get(self, store: Dict, name: str, node: Optional[ast.AST] = None,
             scope: Optional[Scope] = None) -> Optional[object]:
        for key in self._candidates(store, name, node, scope):
            if key in store:
                return store[key]
        return None

    def _has(self, store: Set, name: str, node: Optional[ast.AST] = None,
             scope: Optional[Scope] = None) -> bool:
        return any(key in store for key in self._candidates(store, name, node, scope))

    # ------------------------------------------------------------------
    # Public views
    # ------------------------------------------------------------------

    @property
    def tainted_vars(self) -> Dict[str, TaintOrigin]:
        return {name: origin for (_scope, name), origin in self._b.tainted.items()}

    @property
    def prefix_tainted_vars(self) -> Dict[str, TaintOrigin]:
        return {name: origin for (_scope, name), origin in self._b.prefix_tainted.items()}

    @property
    def set_vars(self) -> Set[str]:
        return {name for (_scope, name) in self._b.sets}

    @property
    def static_prefix_vars(self) -> Dict[str, str]:
        return {name: value for (_scope, name), value in self._b.static.items()}

    @property
    def json_flows(self) -> Dict[Key, Set[int]]:
        """Vars whose value embeds an unsorted ``json.dumps`` call (by node id)."""
        return self._b.json_flows

    def resolve_dict(self, node: ast.AST) -> Optional[ast.Dict]:
        """Dict literal bound to the name in ``node``."""
        if isinstance(node, ast.Dict):
            return node
        if isinstance(node, ast.Name):
            return self._get(self._b.dicts, node.id, node)  # type: ignore[return-value]
        return None

    def resolve_list(self, node: ast.AST) -> Optional[ast.List]:
        """List literal bound to the name in ``node``."""
        if isinstance(node, ast.List):
            return node
        if isinstance(node, ast.Name):
            return self._get(self._b.lists, node.id, node)  # type: ignore[return-value]
        return None

    def mark_tools_mutated(self, var_name: str, node: ast.AST) -> None:
        self._b.tools_mutated.add((self.scope_of(node), var_name))

    def mark_branch_var(self, var_name: str, node: ast.AST) -> None:
        self._b.branch.add((self.scope_of(node), var_name))

    # ------------------------------------------------------------------
    # Queries
    # ------------------------------------------------------------------

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
        length = _static_str_len(node)
        if length is not None:
            return length >= STATIC_SOLID_MIN_CHARS
        if isinstance(node, ast.Name):
            if node.id in STATIC_PREFIX_NAMES or self._get(self._b.static, node.id, node):
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
            origin = self._get(self._b.tainted, node.id, node)
            return origin if origin else None  # type: ignore[return-value]
        if isinstance(node, ast.Attribute):
            return self.get_taint_origin_of_node(node.value)
        if isinstance(node, ast.Call):
            origin = self.is_taint_source(node)
            if origin:
                return origin
            if isinstance(node.func, ast.Name):
                # Result of a local function that returns tainted data.
                func_origin = self._get(self._func_returns, node.func.id, node)
                if func_origin:
                    return func_origin  # type: ignore[return-value]
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
            if self._is_join_call(node) and node.args:
                return self.get_taint_origin_of_node(node.args[0])
            return None
        if isinstance(node, (ast.List, ast.Tuple, ast.Set)):
            for elt in node.elts:
                origin = self.get_taint_origin_of_node(elt)
                if origin:
                    return origin
            return None
        if _is_string_concat(node):
            parts = self._flatten_string_expr(node)
            for part in parts:
                if part is not node:
                    origin = self.get_taint_origin_of_node(part)
                    if origin:
                        return origin
            return None
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
            origin = self.get_taint_origin_of_node(part)
            if origin:
                # A tainted part is never a static solid, even when its name looks static.
                if first_taint_idx == -1:
                    first_taint_idx = idx
                    first_taint_origin = origin
                continue
            if self.is_static_prefix_solid(part):
                static_solid_indices.append(idx)
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

    # ------------------------------------------------------------------
    # Assignment tracking
    # ------------------------------------------------------------------

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

        scope = self.scope_of(node)
        in_branch = self.in_branch(node)
        for var_name in targets:
            # Evaluate the RHS against live state (it may read the name it rebinds),
            # then strong-update that name's bindings.
            buf = _Bindings()
            self._track_target_value(node, var_name, value, buf)
            key = (scope, var_name)
            self._b.clear_key(key)
            self._b.merge(buf)
            self._label_origin(key, var_name)
            if in_branch:
                self._b.branch.add(key)
                if var_name == "tools":
                    self._b.tools_mutated.add(key)

    def _label_origin(self, key: Key, var_name: str) -> None:
        """Record which variable an origin was bound to (for diagnostics/debugging)."""
        origin = self._b.tainted.get(key)
        if origin is None or origin.variable_name:
            return
        named = replace(origin, variable_name=var_name)
        self._b.tainted[key] = named
        if key in self._b.prefix_tainted:
            self._b.prefix_tainted[key] = named

    def _track_target_value(self, node: ast.AST, var_name: str, value: ast.AST,
                            buf: _Bindings) -> None:
        scope = self.scope_of(node)
        key = (scope, var_name)

        # 0. Variable alias: e.g. b = a
        if isinstance(value, ast.Name):
            src = value.id
            origin = self._get(self._b.tainted, src, value)
            if origin:
                buf.tainted[key] = origin  # type: ignore[assignment]
            prefix_origin = self._get(self._b.prefix_tainted, src, value)
            if prefix_origin:
                buf.prefix_tainted[key] = prefix_origin  # type: ignore[assignment]
            if self._has(self._b.sets, src, value):
                buf.sets.add(key)
            static = self._get(self._b.static, src, value)
            if static:
                buf.static[key] = static  # type: ignore[assignment]
            if self._has(self._b.tools_mutated, src, value):
                buf.tools_mutated.add(key)
            if self._has(self._b.branch, src, value):
                buf.branch.add(key)
            if self._has(self._b.json_unsorted, src, value):
                buf.json_unsorted.add(key)
            flows = self._get(self._b.json_flows, src, value)
            if flows:
                buf.json_flows[key] = set(flows)  # type: ignore[arg-type]
            lst = self._get(self._b.lists, src, value)
            if lst:
                buf.lists[key] = lst  # type: ignore[assignment]
            dct = self._get(self._b.dicts, src, value)
            if dct:
                buf.dicts[key] = dct  # type: ignore[assignment]
            return

        # 1. Dict expressions
        if isinstance(value, ast.Dict):
            buf.dicts[key] = value

        # 2. List expressions
        if isinstance(value, ast.List):
            buf.lists[key] = value

        # 3. Set expressions
        if isinstance(value, (ast.Set, ast.SetComp)):
            buf.sets.add(key)
            if var_name == "tools":
                buf.tools_mutated.add(key)
            self._track_json_and_branch(var_name, value, scope, buf)
            return

        # 4. Calls
        if isinstance(value, ast.Call):
            if self._is_set_call(value):
                buf.sets.add(key)
                if var_name == "tools":
                    buf.tools_mutated.add(key)
                self._track_json_and_branch(var_name, value, scope, buf)
                return

            if self._is_shuffle_call(value):
                buf.tools_mutated.add(key)
                self._track_json_and_branch(var_name, value, scope, buf)
                return

            # Check if list constructed from set: list(my_set)
            if isinstance(value.func, ast.Name) and value.func.id == "list" and value.args:
                arg = value.args[0]
                if (isinstance(arg, ast.Name) and self.is_set_variable(arg.id, arg)) \
                        or isinstance(arg, (ast.Set, ast.SetComp)):
                    buf.tools_mutated.add(key)

            if self._is_json_dumps(value) and not _has_sort_keys(value):
                buf.json_unsorted.add(key)

            if self._is_file_read(value):
                if var_name.isupper():
                    buf.static[key] = "file_read"
                self._track_json_and_branch(var_name, value, scope, buf)
                return

        # 5. List comprehension iterating over set: [t for t in tool_set]
        if isinstance(value, ast.ListComp):
            for gen in value.generators:
                if (isinstance(gen.iter, ast.Name) and self.is_set_variable(gen.iter.id, gen.iter)) \
                        or isinstance(gen.iter, (ast.Set, ast.SetComp)):
                    buf.tools_mutated.add(key)

        # 6. String constant assigned to UPPER_CASE variable
        if isinstance(value, ast.Constant) and isinstance(value.value, str):
            if var_name.isupper():
                buf.static[key] = value.value
            return

        # 7. JoinedStr (f-string) and BinOp (+) string concatenation
        if _is_string_concat(value):
            parts = self._flatten_string_expr(value)
            origin = self.check_sequence_prefix_taint(parts)
            if origin:
                buf.tainted[key] = origin
                buf.prefix_tainted[key] = origin
            else:
                for part in parts:
                    if part is not value:
                        p_orig = self.get_taint_origin_of_node(part)
                        if p_orig:
                            buf.tainted[key] = p_orig
                            break
            self._track_json_and_branch(var_name, value, scope, buf)
            return

        # 8. Format call: "...".format(...)
        if isinstance(value, ast.Call) and self._is_format_call(value):
            parts = list(value.args) + [kw.value for kw in value.keywords if kw.value]
            origin = self.check_sequence_prefix_taint(parts) if parts else None
            if origin:
                buf.tainted[key] = origin
                buf.prefix_tainted[key] = origin
            else:
                any_orig = self._find_origin_in_format(value)
                if any_orig:
                    buf.tainted[key] = any_orig
            self._track_json_and_branch(var_name, value, scope, buf)
            return

        # 9. General taint origin
        origin = self.get_taint_origin_of_node(value)
        if origin:
            buf.tainted[key] = origin
            buf.prefix_tainted[key] = origin
        self._track_json_and_branch(var_name, value, scope, buf)

    def _track_json_and_branch(self, var_name: str, value: ast.AST, scope: Scope,
                               buf: _Bindings) -> None:
        """Record unsorted-json provenance and branch-conditional construction."""
        key = (scope, var_name)
        flows = self._unsorted_json_nodes(value)
        if flows:
            buf.json_flows[key] = flows
        if self._references_branch_var(value):
            buf.branch.add(key)

    def _unsorted_json_nodes(self, node: ast.AST) -> Set[int]:
        """Ids of unsorted ``json.dumps`` calls that flow into ``node``."""
        out: Set[int] = set()
        for sub in ast.walk(node):
            if isinstance(sub, ast.Call) and self._is_json_dumps(sub) and not _has_sort_keys(sub):
                out.add(id(sub))
            elif isinstance(sub, ast.Name):
                flows = self._get(self._b.json_flows, sub.id, sub)
                if flows:
                    out |= set(flows)  # type: ignore[arg-type]
        return out

    def _references_branch_var(self, node: ast.AST) -> bool:
        """True when the expression reads a name that is only set on some branches."""
        for sub in ast.walk(node):
            if isinstance(sub, ast.Name) and self._has(self._b.branch, sub.id, sub):
                return True
        return False

    def track_aug_assign(self, node: ast.AugAssign) -> None:
        """Track augmented assignments like messages += [...] or tools += [...]."""
        if isinstance(node.target, ast.Name):
            scope = self.scope_of(node)
            key = (scope, node.target.id)
            current = self._get(self._b.lists, node.target.id, node)
            if current and isinstance(node.value, ast.List):
                current.elts.extend(node.value.elts)  # type: ignore[union-attr]
            if node.target.id == "tools":
                self._b.tools_mutated.add(key)
            if self.in_branch(node):
                self._b.branch.add(key)
            if _is_string_concat(node.value):
                parts = self._flatten_string_expr(node.value)
                origin = self.check_sequence_prefix_taint(parts)
                if origin:
                    self._b.tainted[key] = origin
                    self._b.prefix_tainted[key] = origin
                    self._label_origin(key, node.target.id)

    def track_expr_stmt(self, node: ast.Expr) -> None:
        """Track standalone expressions such as random.shuffle(tools) or list.append()."""
        if isinstance(node.value, ast.Call):
            if self._is_shuffle_call(node.value):
                if node.value.args and isinstance(node.value.args[0], ast.Name):
                    self.mark_tools_mutated(node.value.args[0].id, node.value.args[0])
            if isinstance(node.value.func, ast.Attribute):
                attr = node.value.func.attr
                caller = node.value.func.value
                if isinstance(caller, ast.Name):
                    if attr in ("append", "extend", "insert") and self.in_branch(node):
                        self.mark_tools_mutated(caller.id, caller)
                    if attr == "append" and node.value.args:
                        lst = self._get(self._b.lists, caller.id, caller)
                        if lst:
                            lst.elts.append(node.value.args[0])  # type: ignore[union-attr]
                    elif attr == "extend" and node.value.args:
                        arg = node.value.args[0]
                        lst = self._get(self._b.lists, caller.id, caller)
                        if lst and isinstance(arg, ast.List):
                            lst.elts.extend(arg.elts)
                        if isinstance(arg, ast.Name) and self.is_set_variable(arg.id, arg):
                            self.mark_tools_mutated(caller.id, caller)

    # ------------------------------------------------------------------
    # Function-return taint (one level of inter-procedural flow)
    # ------------------------------------------------------------------

    def build_function_returns(self, tree: ast.AST) -> bool:
        """Resolve taint origins produced by ``return`` statements.

        Returns True when a new function return origin was recorded.
        """
        returns: Dict[Scope, List[ast.AST]] = {}
        defs: Dict[Scope, List[str]] = {}
        for node in ast.walk(tree):
            if isinstance(node, ast.Return) and node.value is not None:
                returns.setdefault(self.scope_of(node), []).append(node.value)
            elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                defs.setdefault(self.scope_of(node), []).append(node.name)

        changed = False
        for def_scope, names in defs.items():
            for name in names:
                fn_scope = def_scope + (name,)
                origin = None
                for ret in returns.get(fn_scope, ()):
                    origin = self.get_taint_origin_of_node(ret)
                    if origin:
                        break
                if origin is None:
                    continue
                func_key = (def_scope, name)
                if self._func_returns.get(func_key) != origin:
                    self._func_returns[func_key] = origin
                    changed = True
        return changed

    # ------------------------------------------------------------------
    # Call predicates
    # ------------------------------------------------------------------

    def _is_format_call(self, node: ast.Call) -> bool:
        return isinstance(node.func, ast.Attribute) and node.func.attr == "format"

    def _is_join_call(self, node: ast.Call) -> bool:
        return isinstance(node.func, ast.Attribute) and node.func.attr == "join"

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
            origin = self._get(self._b.prefix_tainted, node.id, node)
            return origin if origin else None  # type: ignore[return-value]
        if _is_string_concat(node):
            parts = self._flatten_string_expr(node)
            return self.check_sequence_prefix_taint(parts)
        if isinstance(node, ast.Call):
            origin = self.is_taint_source(node)
            if origin:
                return origin
            if isinstance(node.func, ast.Name):
                func_origin = self._get(self._func_returns, node.func.id, node)
                if func_origin:
                    return func_origin  # type: ignore[return-value]
            if isinstance(node.func, ast.Attribute):
                caller_origin = self.get_taint_origin_of_node(node.func.value)
                if caller_origin:
                    return caller_origin
            if isinstance(node.func, ast.Name) and node.func.id in ("str", "int", "float", "repr", "bytes") and node.args:
                return self.get_taint_origin_of_node(node.args[0])
            if self._is_format_call(node):
                return self._find_origin_in_format(node)
            if self._is_join_call(node) and node.args:
                return self.get_taint_origin_of_node(node.args[0])
        if isinstance(node, (ast.List, ast.Tuple, ast.Set)):
            for elt in node.elts:
                origin = self.get_taint_origin_of_node(elt)
                if origin:
                    return origin
        return None

    def is_tainted_variable(self, var_name: str, node: Optional[ast.AST] = None) -> bool:
        return self._has(self._b.tainted, var_name, node)

    def is_set_variable(self, var_name: str, node: Optional[ast.AST] = None) -> bool:
        return self._has(self._b.sets, var_name, node)

    def is_tools_mutated(self, var_name: str, node: Optional[ast.AST] = None) -> bool:
        return self._has(self._b.tools_mutated, var_name, node)

    def is_json_unsorted(self, var_name: str, node: Optional[ast.AST] = None) -> bool:
        return self._has(self._b.json_unsorted, var_name, node)

    def is_branch_var(self, var_name: str, node: Optional[ast.AST] = None) -> bool:
        return self._has(self._b.branch, var_name, node)
