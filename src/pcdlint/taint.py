"""Static taint and prefix tracking engine for pcdlint."""

import ast
from collections.abc import Iterable, Iterator, Mapping
from contextlib import contextmanager
from dataclasses import replace
from typing import TypeVar

from pcdlint.models import FuncSummary, TaintOrigin

# A lexical scope path, e.g. ("module",) or ("module", "handler", "inner").
Scope = tuple[str, ...]
MODULE_SCOPE: Scope = ("module",)
# Scope-qualified binding key.
Key = tuple[Scope, str]
# Value type of a binding table, so _get() returns the table's own value type.
_V = TypeVar("_V")

TAINT_SOURCES: dict[tuple, str] = {
    # Key is (module or class, member); value is the fully qualified call name
    # a resolved chain is matched against, at a dot boundary -- so
    # `datetime.date.today` matches `date.today` while `event.time` does not
    # match `time.time`.
    ("datetime", "now"): "datetime.now",
    ("datetime", "utcnow"): "datetime.utcnow",
    ("datetime", "today"): "datetime.today",
    ("date", "today"): "date.today",
    ("time", "time"): "time.time",
    ("time", "time_ns"): "time.time_ns",
    ("time", "monotonic"): "time.monotonic",
    ("time", "perf_counter"): "time.perf_counter",
    ("time", "strftime"): "time.strftime",
    ("time", "ctime"): "time.ctime",
    ("time", "localtime"): "time.localtime",
    ("time", "gmtime"): "time.gmtime",
    ("uuid", "uuid4"): "uuid.uuid4",
    ("uuid", "uuid1"): "uuid.uuid1",
    ("uuid", "uuid6"): "uuid.uuid6",
    ("uuid", "uuid7"): "uuid.uuid7",
    ("random", "random"): "random.random",
    ("random", "randint"): "random.randint",
    ("random", "choice"): "random.choice",
    ("random", "choices"): "random.choices",
    ("random", "sample"): "random.sample",
    ("random", "randrange"): "random.randrange",
    ("random", "uniform"): "random.uniform",
    ("random", "getrandbits"): "random.getrandbits",
    ("secrets", "token_hex"): "secrets.token_hex",
    ("secrets", "token_urlsafe"): "secrets.token_urlsafe",
    ("secrets", "token_bytes"): "secrets.token_bytes",
    ("os", "urandom"): "os.urandom",
    ("os", "getpid"): "os.getpid",
    # django.utils.timezone.now, reached through `from django.utils import
    # timezone` (which the import table expands) or written out in full.
    ("timezone", "now"): "timezone.now",
    # pandas, reached through `import pandas as pd`.
    ("Timestamp", "now"): "Timestamp.now",
}

# Sources that only read the clock when the caller leaves the time out. The
# value is how many positional arguments make the call a pure function of
# them: time.strftime(fmt, t), time.ctime(secs), time.localtime(secs),
# time.gmtime(secs). Below that count the result varies between runs.
_TIME_PARAM_SOURCES: dict[str, int] = {
    "time.strftime": 2,
    "time.ctime": 1,
    "time.localtime": 1,
    "time.gmtime": 1,
}

STATIC_PREFIX_NAMES: set[str] = {
    "SYSTEM_PROMPT", "KNOWLEDGE_BASE", "STATIC_RULES",
    "PROMPT", "SYSTEM_MESSAGE", "PREFIX", "HEADER", "STATIC_PROMPT",
}

# A literal this long is treated as a cache-safe static prefix solid.
STATIC_SOLID_MIN_CHARS = 200
# Bound for repeated-string length math ("x" * huge) so evaluation stays cheap.
_MAX_STATIC_CHARS = 1_000_000


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


def _static_str_len(node: ast.AST) -> int | None:
    """Length of a statically evaluable string expression, or None.

    Handles string constants plus concatenation and repetition
    (``"rules " * 30``), a common way to build long static prefixes.

    The walk is explicit rather than recursive: ``a + a + a + ...`` nests
    left, so its depth grows with operand count, and ``ast.parse`` accepts
    concatenations far past what Python's own stack can hold. Post-order is
    kept because ``*`` needs both operands measured before it can multiply.
    """
    measured: dict[int, int | None] = {}
    stack: list[tuple[ast.AST, bool]] = [(node, False)]
    while stack:
        current, expanded = stack.pop()
        if not expanded:
            if isinstance(current, ast.Constant):
                measured[id(current)] = (
                    len(current.value) if isinstance(current.value, str) else None
                )
            elif isinstance(current, ast.BinOp) and isinstance(
                current.op, (ast.Add, ast.Mult)
            ):
                stack.append((current, True))
                stack.append((current.right, False))
                stack.append((current.left, False))
            else:
                measured[id(current)] = None
            continue
        if isinstance(current, ast.BinOp) and isinstance(current.op, ast.Add):
            left = measured[id(current.left)]
            right = measured[id(current.right)]
            measured[id(current)] = (
                None if left is None or right is None
                else min(left + right, _MAX_STATIC_CHARS)
            )
            continue
        length = None
        if isinstance(current, ast.BinOp):
            for base, count in ((current.left, current.right),
                                (current.right, current.left)):
                if isinstance(count, ast.Constant) and isinstance(count.value, int) \
                        and not isinstance(count.value, bool):
                    base_len = measured[id(base)]
                    if base_len is not None:
                        length = max(min(base_len * count.value, _MAX_STATIC_CHARS), 0)
                        break
        measured[id(current)] = length
    return measured.get(id(node))


def _assign_pairs(target: ast.expr, value: ast.AST | None,
                  out: list[tuple[str, ast.AST]]) -> None:
    """Pair each assignment target with the expression that binds it.

    A Name takes the whole right-hand side. A Tuple/List target pairs
    element-wise with a Tuple/List value of the same length; anything else
    -- a call that returns a pair, a star-unpack, a length mismatch -- is
    not something this can see through, and guessing would bind the wrong
    expression to the wrong name.
    """
    if isinstance(target, ast.Name):
        if value is not None:
            out.append((target.id, value))
        return
    if (isinstance(target, (ast.Tuple, ast.List))
            and isinstance(value, (ast.Tuple, ast.List))
            and len(target.elts) == len(value.elts)):
        for element, item in zip(target.elts, value.elts):
            _assign_pairs(element, item, out)


def _has_sort_keys(node: ast.Call) -> bool:
    """True when a json.dumps call passes the literal ``sort_keys=True``."""
    for kw in node.keywords:
        if kw.arg == "sort_keys" and isinstance(kw.value, ast.Constant) and kw.value.value is True:
            return True
    return False


def _elements_orderable(node: ast.AST) -> bool:
    """True when every element of a set literal shares a total order.

    ``sorted()`` needs one: ``sorted({1, "a"})`` raises TypeError, so a fix
    that wraps a set may only wrap one whose elements it can see, all from a
    single comparable family. Ceiling: a set built by a comprehension or a
    call is unknown and is declined rather than guessed at.
    """
    if not isinstance(node, ast.Set) or not node.elts:
        return False
    values: list[object] = []
    for elt in node.elts:
        if not isinstance(elt, ast.Constant):
            return False
        values.append(elt.value)
    # str and bytes are each ordered within their own kind, never across.
    if all(isinstance(v, str) for v in values):
        return True
    if all(isinstance(v, bytes) for v in values):
        return True
    # bool is an int, so this covers {True, 0} as well.
    return all(isinstance(v, (int, float)) for v in values)


def _same_ast(left: ast.AST | None, right: ast.AST | None) -> bool:
    """True when two nodes are the same node or spell the same expression."""
    if left is None or right is None:
        return False
    return left is right or ast.dump(left) == ast.dump(right)


def _child_flags(node: ast.AST, in_cond: bool, in_loop: bool,
                 loop_iter: ast.AST | None, count: int) -> list[tuple[bool, bool, ast.AST | None]]:
    """``(in_conditional, in_loop, loop_iterator)`` for each child of ``node``.

    A *conditional* is an if/elif/else arm, a conditional expression, or a
    try/except arm -- code that provably runs on only some paths. A *loop*
    body may run zero times but is not branchy in the same sense; keeping the
    two apart is what lets a ``for`` over a list literal stay deterministic
    while an ``if`` around the same mutation does not.
    """
    inherit = (in_cond, in_loop, loop_iter)
    if isinstance(node, (ast.If, ast.IfExp, ast.Match)):
        # head child (the test, or a match subject) runs unconditionally;
        # the arms do not.
        return [inherit] + [(True, in_loop, loop_iter)] * (count - 1)
    if isinstance(node, ast.While):
        # head child (the test) runs unconditionally; the body may run zero times.
        return [inherit] + [(in_cond, True, None)] * (count - 1)
    if isinstance(node, (ast.For, ast.AsyncFor)):
        # target and iter run unconditionally; body/orelse do not.
        return [inherit, inherit] + [(in_cond, True, node.iter)] * (count - 2)
    if isinstance(node, (ast.Try, ast.ExceptHandler)):
        return [(True, in_loop, loop_iter)] * count
    return [inherit] * count


class _Bindings:
    """Scope-keyed binding tables produced by one tracking pass."""

    __slots__ = (
        "branch",
        "dicts",
        "json_flows",
        "json_unsorted",
        "lists",
        "prefix_tainted",
        "set_orderable",
        "sets",
        "static",
        "static_len",
        "strings",
        "tainted",
        "tools_mutated",
    )

    def __init__(self) -> None:
        self.tainted: dict[Key, TaintOrigin] = {}
        self.prefix_tainted: dict[Key, TaintOrigin] = {}
        self.sets: set[Key] = set()
        self.static: dict[Key, str] = {}
        # Characters of static text known to be bound to the name, whether or
        # not it is shouty. This is what lets ``prompt = STATIC; prompt +=
        # f"{now}"`` be seen as taint *after* a solid prefix rather than
        # taint at the start of one.
        self.static_len: dict[Key, int] = {}
        self.tools_mutated: set[Key] = set()
        self.branch: set[Key] = set()
        self.json_unsorted: set[Key] = set()
        self.json_flows: dict[Key, set[int]] = {}
        self.lists: dict[Key, ast.List] = {}
        self.dicts: dict[Key, ast.Dict] = {}
        # Sets whose elements provably share a total order. Only these may be
        # handed to sorted() by --fix: sorted() on {1, "a"} raises TypeError.
        self.set_orderable: set[Key] = set()
        # Names bound to a str/bytes value, which is what decides whether
        # hash(name) is salted by PYTHONHASHSEED.
        self.strings: set[Key] = set()

    def merge(self, other: "_Bindings") -> None:
        self.tainted.update(other.tainted)
        self.prefix_tainted.update(other.prefix_tainted)
        self.sets.update(other.sets)
        self.static.update(other.static)
        self.static_len.update(other.static_len)
        self.tools_mutated.update(other.tools_mutated)
        self.branch.update(other.branch)
        self.json_unsorted.update(other.json_unsorted)
        self.set_orderable.update(other.set_orderable)
        self.strings.update(other.strings)
        for key, flows in other.json_flows.items():
            self.json_flows.setdefault(key, set()).update(flows)
        self.lists.update(other.lists)
        self.dicts.update(other.dicts)

    def copy(self) -> "_Bindings":
        """Shallow copy of every container, so sibling paths can diverge."""
        clone = _Bindings()
        clone.tainted = dict(self.tainted)
        clone.prefix_tainted = dict(self.prefix_tainted)
        clone.sets = set(self.sets)
        clone.static = dict(self.static)
        clone.static_len = dict(self.static_len)
        clone.tools_mutated = set(self.tools_mutated)
        clone.branch = set(self.branch)
        clone.json_unsorted = set(self.json_unsorted)
        clone.set_orderable = set(self.set_orderable)
        clone.json_flows = {k: set(v) for k, v in self.json_flows.items()}
        clone.lists = dict(self.lists)
        clone.dicts = dict(self.dicts)
        clone.strings = set(self.strings)
        return clone

    def paths_agree(self, key: Key, other: "_Bindings") -> bool:
        """True only when both paths bound ``key`` to structurally equal values.

        Reporting "these two arms are the same" needs evidence. When neither
        path holds a list or dict literal for the name there is nothing to
        compare, so the caller keeps its flag rather than clearing it.
        """
        for mine, theirs in ((self.lists.get(key), other.lists.get(key)),
                             (self.dicts.get(key), other.dicts.get(key))):
            if mine is not None or theirs is not None:
                return _same_ast(mine, theirs)
        return False

    def merge_path(self, other: "_Bindings") -> None:
        """May-merge a sibling control-flow path into this one.

        Taint-like stores are unioned: a value reached on either arm is a
        value the runtime can see. ``static`` is the opposite -- a name only
        counts as static text when every path binds it identically.
        """
        for key, origin in other.tainted.items():
            self.tainted.setdefault(key, origin)
        for key, origin in other.prefix_tainted.items():
            self.prefix_tainted.setdefault(key, origin)
        self.sets |= other.sets
        self.tools_mutated |= other.tools_mutated
        self.json_unsorted |= other.json_unsorted
        self.strings |= other.strings
        # Intersection, not union: orderability is a safety claim, so it only
        # survives when every arm that rebinds the name proves it. An arm that
        # did not rebind keeps the pre-branch value, which is in both sides.
        self.set_orderable &= other.set_orderable
        for key, flows in other.json_flows.items():
            self.json_flows.setdefault(key, set()).update(flows)

        for key in list(self.static):
            if other.static.get(key) != self.static[key]:
                del self.static[key]
        for key in list(self.static_len):
            if other.static_len.get(key) != self.static_len[key]:
                del self.static_len[key]

        # Structural bindings are a resolution aid, not a claim: keep the one
        # that exists, preferring this path when both arms bound the name.
        for key, lst in other.lists.items():
            self.lists.setdefault(key, lst)
        for key, dct in other.dicts.items():
            self.dicts.setdefault(key, dct)

        # The conditional flag survives only when the arms provably differ.
        self.branch |= other.branch
        for key in list(self.branch):
            if key in other.branch and self.paths_agree(key, other):
                self.branch.discard(key)

    def clear_key(self, key: Key) -> None:
        """Drop every binding for one name (strong update on reassignment)."""
        for store in (self.tainted, self.prefix_tainted, self.static,
                      self.static_len, self.json_flows, self.lists, self.dicts):
            store.pop(key, None)
        # Separate name: these are sets, and the dict stores above would
        # otherwise drive mypy's inference for both loops.
        for set_store in (self.sets, self.tools_mutated, self.branch,
                          self.json_unsorted, self.set_orderable,
                          self.strings):
            set_store.discard(key)


class TaintTracker:
    """Tracks tainted variables and static prefix solids across an AST."""

    def __init__(self) -> None:
        self._node_scope: dict[int, Scope] = {}
        self._node_branch: dict[int, bool] = {}
        self._node_cond: dict[int, bool] = {}
        self._node_loop: dict[int, bool] = {}
        self._node_loop_iter: dict[int, ast.AST | None] = {}
        self._b = _Bindings()
        self._func_summaries: dict[Key, FuncSummary] = {}
        # Local names bound to stdlib json: ``import json as J`` spells the
        # same non-determinism as ``json.dumps`` and must be recognised.
        self._json_modules: set[str] = set()
        self._json_dumps: set[str] = set()
        # Local name -> the fully qualified name it stands for, so
        # ``import random as rnd`` and ``from uuid import uuid4 as u`` still
        # resolve back to the module they came from.
        self._imports: dict[str, str] = {}
        # Statement id -> ids of the LLM calls worth snapshotting, and the
        # snapshots themselves. Rules must judge a call against the state it
        # ran in, not the state the file ended in; see freeze_for()/at().
        self._sink_calls: dict[int, list[int]] = {}
        self._frozen: dict[int, _Bindings] = {}

    def set_sink_calls(self, mapping: dict[int, list[int]]) -> None:
        """Tell the tracker which calls to snapshot, and under which statement."""
        self._sink_calls = mapping

    def freeze_for(self, node: ast.AST) -> None:
        """Snapshot the live bindings for every call ``node`` is about to run.

        Called just before the statement is tracked, because that is the
        state its arguments are evaluated in. Re-running each pass overwrites
        the earlier snapshot, so the last pass wins.
        """
        for call_id in self._sink_calls.get(id(node), ()):
            self._frozen[call_id] = self._b.copy()

    @contextmanager
    def at(self, node: ast.AST) -> Iterator[None]:
        """Resolve against the bindings ``node`` was recorded with, if any.

        A call with no snapshot -- inside a function, whose execution point
        nobody can know -- falls through to the live, whole-file state.
        """
        snapshot = self._frozen.get(id(node))
        if snapshot is None:
            yield
            return
        live = self._b
        self._b = snapshot.copy()
        try:
            yield
        finally:
            self._b = live

    # ------------------------------------------------------------------
    # Scopes and branch positions
    # ------------------------------------------------------------------

    def build_scopes(self, tree: ast.AST) -> None:
        """Map every node to its lexical scope and branch position.

        Import bindings ride along on the same walk: ``J.dumps`` only means
        ``json.dumps`` because some earlier line said ``import json as J``,
        and ``rnd.choice`` only means ``random.choice`` for the same reason.
        They are queued as ``(lineno, col, local, qualified)`` and applied in
        source order afterwards, because the walk visits siblings newest
        first and Python resolves the *last* binding of a name. Ceiling:
        bindings are tracked as if file-global, so a local ``import json``
        inside a function still counts for the whole file.
        """
        records: list[tuple[int, int, str, str]] = []
        stack: list[tuple[ast.AST, Scope, bool, bool, ast.AST | None]] = [
            (tree, MODULE_SCOPE, False, False, None),
        ]
        while stack:
            node, scope, in_cond, in_loop, loop_iter = stack.pop()
            self._node_scope[id(node)] = scope
            self._node_branch[id(node)] = in_cond or in_loop
            self._node_cond[id(node)] = in_cond
            self._node_loop[id(node)] = in_loop
            self._node_loop_iter[id(node)] = loop_iter
            self._record_imports(node, records)
            child_scope = scope
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                child_scope = scope + (node.name,)
            children = list(ast.iter_child_nodes(node))
            flags = _child_flags(node, in_cond, in_loop, loop_iter, len(children))
            for child, (c_cond, c_loop, c_iter) in zip(children, flags):
                stack.append((child, child_scope, c_cond, c_loop, c_iter))
        for _lineno, _col, local, qualified in sorted(records):
            self._imports[local] = qualified

    def _record_imports(self, node: ast.AST,
                        records: list[tuple[int, int, str, str]]) -> None:
        """Queue how this file spells stdlib json and its other imports."""
        if isinstance(node, ast.Import):
            for alias in node.names:
                # `import a.b` binds only `a` (to `a`); `import a.b as z`
                # binds `z` to `a.b`.
                top = alias.name.split(".")[0]
                records.append((node.lineno, node.col_offset,
                                alias.asname or top,
                                alias.name if alias.asname else top))
                if alias.name == "json":
                    self._json_modules.add(alias.asname or alias.name)
        elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
            for alias in node.names:
                if alias.name == "*":
                    continue
                local = alias.asname or alias.name
                records.append((node.lineno, node.col_offset, local,
                                f"{node.module}.{alias.name}"))
                if node.module == "json" and alias.name == "dumps":
                    self._json_dumps.add(local)

    def scope_of(self, node: ast.AST) -> Scope:
        """Lexical scope of a node (module scope when unknown)."""
        return self._node_scope.get(id(node), MODULE_SCOPE)

    def in_branch(self, node: ast.AST) -> bool:
        """True when the node only runs on some paths (if/loop/try body)."""
        return self._node_branch.get(id(node), False)

    def in_conditional(self, node: ast.AST) -> bool:
        """True inside an if/elif/else, conditional expression, or try arm."""
        return self._node_cond.get(id(node), False)

    def loop_iterator(self, node: ast.AST) -> ast.AST | None:
        """The iterable of the innermost loop ``node`` sits in, if any."""
        if not self._node_loop.get(id(node), False):
            return None
        return self._node_loop_iter.get(id(node))

    # ------------------------------------------------------------------
    # Control-flow snapshots
    # ------------------------------------------------------------------

    def snapshot(self) -> "_Bindings":
        """Freeze the live bindings so a sibling path can start from them."""
        return self._b.copy()

    def restore(self, state: "_Bindings") -> None:
        """Replace the live bindings with a previously frozen state."""
        self._b = state

    def merge_path(self, other: "_Bindings") -> None:
        """Merge a sibling path's bindings into the live state."""
        self._b.merge_path(other)

    def _candidates(self, store: Iterable[Key], name: str,
                    node: ast.AST | None, scope: Scope | None) -> Iterator[Key]:
        """Keys to try for ``name``, innermost scope first."""
        if scope is None:
            scope = self.scope_of(node) if node is not None else None
        if scope is None:
            # Legacy bare-name lookup: module scope, then any other scope.
            yield (MODULE_SCOPE, name)
            for key in store:
                if key[1] == name and key != (MODULE_SCOPE, name):
                    yield key
            return
        for i in range(len(scope), 0, -1):
            yield (scope[:i], name)

    def _get(self, store: Mapping[Key, _V], name: str, node: ast.AST | None = None,
             scope: Scope | None = None) -> _V | None:
        for key in self._candidates(store, name, node, scope):
            if key in store:
                return store[key]
        return None

    def _has(self, store: Iterable[Key], name: str, node: ast.AST | None = None,
             scope: Scope | None = None) -> bool:
        return any(key in store for key in self._candidates(store, name, node, scope))

    # ------------------------------------------------------------------
    # Public views
    # ------------------------------------------------------------------

    @property
    def tainted_vars(self) -> dict[str, TaintOrigin]:
        return {name: origin for (_scope, name), origin in self._b.tainted.items()}

    @property
    def prefix_tainted_vars(self) -> dict[str, TaintOrigin]:
        return {name: origin for (_scope, name), origin in self._b.prefix_tainted.items()}

    @property
    def set_vars(self) -> set[str]:
        return {name for (_scope, name) in self._b.sets}

    @property
    def static_prefix_vars(self) -> dict[str, str]:
        return {name: value for (_scope, name), value in self._b.static.items()}

    @property
    def json_flows(self) -> dict[Key, set[int]]:
        """Vars whose value embeds an order-unstable expression, by node id.

        Shared by PCL002 (unsorted ``json.dumps``) and PCL003 (set iterated
        without ``sorted()``); each rule looks up only its own node ids.
        """
        return self._b.json_flows

    def resolve_dict(self, node: ast.AST) -> ast.Dict | None:
        """Dict literal bound to the name in ``node``."""
        if isinstance(node, ast.Dict):
            return node
        if isinstance(node, ast.Name):
            return self._get(self._b.dicts, node.id, node)
        return None

    def resolve_list(self, node: ast.AST) -> ast.List | None:
        """List literal bound to the name in ``node``."""
        if isinstance(node, ast.List):
            return node
        if isinstance(node, ast.Name):
            return self._get(self._b.lists, node.id, node)
        return None

    def mark_tools_mutated(self, var_name: str, node: ast.AST) -> None:
        self._b.tools_mutated.add((self.scope_of(node), var_name))

    def mark_branch_var(self, var_name: str, node: ast.AST) -> None:
        self._b.branch.add((self.scope_of(node), var_name))

    # ------------------------------------------------------------------
    # Queries
    # ------------------------------------------------------------------

    def _resolve_parts(self, parts: list[str]) -> str:
        """Expand the leading identifier of a dotted chain through the imports.

        ``rnd.choice`` only means ``random.choice`` because a line said
        ``import random as rnd``; without that, the spelling says nothing.
        """
        if not parts:
            return ""
        base = self._imports.get(parts[0])
        if base is None:
            return ".".join(parts)
        return ".".join([base, *parts[1:]])

    @staticmethod
    def _matched_source(name: str) -> str | None:
        """TAINT_SOURCES entry that ``name`` spells, or None.

        Matching is exact or on a dot boundary, never a substring: that is
        what keeps ``event.time`` from matching ``time.time`` while letting
        ``datetime.date.today`` match ``date.today``.
        """
        if not name:
            return None
        for full in TAINT_SOURCES.values():
            if name == full or name.endswith("." + full):
                return full
        return None

    def _value_is_stringy(self, node: ast.AST) -> bool:
        """True when ``node`` is statically a str or bytes expression.

        Decides whether ``hash(...)`` is salted by PYTHONHASHSEED: hashing a
        number is a pure function of it, hashing a string is not.
        """
        if isinstance(node, ast.Constant):
            return isinstance(node.value, (str, bytes))
        if isinstance(node, ast.JoinedStr):
            return True
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
            return (self._value_is_stringy(node.left)
                    or self._value_is_stringy(node.right))
        if isinstance(node, ast.Name):
            return self._has(self._b.strings, node.id, node)
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
            return node.func.id in ("str", "bytes", "repr")
        return False

    def is_taint_source(self, node: ast.Call) -> TaintOrigin | None:
        """Check if an ast.Call is a known non-deterministic taint source."""
        dotted = _extract_dotted_name(node.func)
        if not dotted:
            return None
        name = self._resolve_parts(dotted.split("."))

        # hash() is a builtin, so it never arrives through the import table.
        if name == "hash" and node.args and self._value_is_stringy(node.args[0]):
            return TaintOrigin(variable_name="", source_call="hash",
                               lineno=node.lineno)

        full = self._matched_source(name)
        if full is None:
            return None
        # time.strftime(fmt, t) and friends only vary when the caller leaves
        # the time out; with it they are pure functions of the argument.
        enough_args = _TIME_PARAM_SOURCES.get(full)
        if enough_args is not None and len(node.args) >= enough_args:
            return None
        return TaintOrigin(variable_name="", source_call=full, lineno=node.lineno)

    def is_static_prefix_solid(self, node: ast.AST) -> bool:
        """Check if node is a heavy static content string or static constant variable."""
        if isinstance(node, ast.FormattedValue):
            return self.is_static_prefix_solid(node.value)
        length = _static_str_len(node)
        if length is not None:
            return length >= STATIC_SOLID_MIN_CHARS
        if isinstance(node, ast.Name):
            if node.id in STATIC_PREFIX_NAMES:
                return True
            # Only a value we watched get bound counts. Shouty case on its own
            # says nothing: ``GREETING = input(...)`` is uppercase and dynamic,
            # and calling it static mutes every taint sitting after it.
            if self._get(self._b.static, node.id, node):
                return True
            # A lowercase name earns the same trust, but only once enough
            # static text is actually bound to it: ``greeting = "hi"`` must
            # not mute the taint that follows it, while a 500-character rules
            # block assigned to ``prompt`` must.
            return self.known_static_len(node.id, node) >= STATIC_SOLID_MIN_CHARS
        return False

    def known_static_len(self, name: str, node: ast.AST | None = None) -> int:
        """Characters of static text known to be bound to ``name`` (0 if unknown).

        Deliberately a measurement, not a verdict: ``STATIC_PREFIX_NAMES``
        members are solids by name for ``is_static_prefix_solid``, but
        ``SYSTEM_PROMPT = "head: "`` is six characters of static text, and
        six characters must not mute the taint appended to it.
        """
        return self._get(self._b.static_len, name, node) or 0

    def _leading_static_len(self, parts: list[ast.AST]) -> int:
        """Statically known characters before the first dynamic part.

        Stops at the first part that is neither a static literal nor a name
        bound to static text: anything past an unknown part cannot be shown
        to sit after static content, and guessing would mute real taint.
        """
        total = 0
        for part in parts:
            if isinstance(part, ast.FormattedValue):
                part = part.value
            if self.get_taint_origin_of_node(part):
                break
            length = _static_str_len(part)
            if length is not None:
                total += length
                continue
            if isinstance(part, ast.Name):
                known = self.known_static_len(part.id, part)
                if not known:
                    break
                total += known
                continue
            break
        return total

    def _flatten_string_expr(self, node: ast.AST) -> list[ast.AST]:
        """Flatten nested BinOp(op=Add) and JoinedStr into an ordered list of part nodes.

        Iterative for the same reason as ``_static_str_len``: ``+`` nests
        left, so chain depth tracks operand count rather than nesting depth.
        ``JoinedStr`` values are pushed back on rather than emitted directly
        so a mixed ``f"{x}a{y}"`` keeps source order.
        """
        parts: list[ast.AST] = []
        pending: list[ast.AST] = [node]
        while pending:
            current = pending.pop()
            if isinstance(current, ast.BinOp) and isinstance(current.op, ast.Add):
                pending.append(current.right)
                pending.append(current.left)
            elif isinstance(current, ast.JoinedStr):
                for val in reversed(current.values):
                    pending.append(
                        val.value if isinstance(val, ast.FormattedValue) else val
                    )
            else:
                parts.append(current)
        return parts

    def _subscript_origin(self, node: ast.Subscript) -> TaintOrigin | None:
        """Taint behind ``base[key]``.

        The key does not make the value constant. When the slice is a
        literal and the dict has no ``**``, the lookup is exact -- so a
        dict holding the time under one key does not make every other key
        dynamic. Anything else (a computed key, a ``**`` merge we cannot
        see into) falls back to asking about every value.
        """
        origin = self.get_taint_origin_of_node(node.value)
        if origin:
            return origin
        resolved = self.resolve_dict(node.value)
        if resolved is None:
            return None
        has_spread = any(key is None for key in resolved.keys)
        if not has_spread and isinstance(node.slice, ast.Constant):
            wanted = node.slice.value
            values = [value for key, value in zip(resolved.keys, resolved.values)
                      if isinstance(key, ast.Constant) and key.value == wanted]
        else:
            values = list(resolved.values)
        for value in values:
            origin = self.get_taint_origin_of_node(value)
            if origin:
                return origin
        return None

    def get_taint_origin_of_node(self, node: ast.AST) -> TaintOrigin | None:
        """Resolve TaintOrigin from an AST node if it contains taint."""
        if isinstance(node, (ast.Await, ast.NamedExpr)):
            return self.get_taint_origin_of_node(node.value)
        if isinstance(node, ast.Subscript):
            return self._subscript_origin(node)
        if isinstance(node, ast.FormattedValue):
            return self.get_taint_origin_of_node(node.value)
        if isinstance(node, ast.IfExp):
            # Either arm can be the value that runs, so taint on one is taint.
            for arm in (node.body, node.orelse):
                origin = self.get_taint_origin_of_node(arm)
                if origin:
                    return origin
            return None
        if isinstance(node, ast.Name):
            origin = self._get(self._b.tainted, node.id, node)
            return origin if origin else None
        if isinstance(node, ast.Attribute):
            return self.get_taint_origin_of_node(node.value)
        if isinstance(node, ast.Call):
            origin = self.is_taint_source(node)
            if origin:
                return origin
            if isinstance(node.func, ast.Name):
                # Result of a local function that returns tainted data.
                summary = self._get(self._func_summaries, node.func.id, node)
                if summary and summary.origin:
                    return summary.origin
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
        if isinstance(node, ast.UnaryOp):
            return self.get_taint_origin_of_node(node.operand)
        if isinstance(node, ast.BinOp) and not isinstance(node.op, ast.Add):
            # Arithmetic on a dynamic value is still dynamic: `time.time() *
            # 1000` is a timestamp, and `-tainted` is tainted. Only `+` is
            # excluded, because it has the string-ordering rules above.
            for operand in (node.left, node.right):
                origin = self.get_taint_origin_of_node(operand)
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

    def check_sequence_prefix_taint(self, parts: list[ast.AST],
                                    preceding_chars: int = 0) -> TaintOrigin | None:
        """Determine if a sequence of string parts contains prefix taint.

        Rules:
        - If a tainted expression appears BEFORE a static prefix solid, it is PREFIX_TAINTED.
        - If a static prefix solid appears FIRST and taint only appears AFTER it (with no
          subsequent static solid), it is NOT prefix-tainted (cache prefix is preserved).
        - If there is NO static prefix solid, but a tainted expression appears at index 0 or
          within the first 500 characters of static text, it is PREFIX_TAINTED.

        ``preceding_chars`` is static text already bound to the name this
        expression is being appended to -- text that is in the string but not
        in ``parts``, because the augmented assignment's target is not one of
        its operands.
        """
        first_taint_idx = -1
        first_taint_origin: TaintOrigin | None = None
        static_solid_indices: list[int] = []
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

        # A solid bound before this expression is a solid at index -1: it
        # precedes every part, so taint anywhere here follows static text.
        if preceding_chars >= STATIC_SOLID_MIN_CHARS:
            return None

        # Rule 1: Taint appears BEFORE any static solid
        for solid_idx in static_solid_indices:
            if solid_idx > first_taint_idx:
                return first_taint_origin

        # Rule 2: Static solid appears FIRST, taint only appears at end
        if static_solid_indices and all(s_idx < first_taint_idx for s_idx in static_solid_indices):
            return None

        # Rule 3: No static solid, taint within first 500 characters of static text
        if not static_solid_indices \
                and static_chars_before_first_taint + preceding_chars < 500:
            return first_taint_origin

        return None

    # ------------------------------------------------------------------
    # Assignment tracking
    # ------------------------------------------------------------------

    def track_assignment(self, node: ast.AST) -> None:
        """Analyze an assignment statement (Assign or AnnAssign) and update states."""
        pairs: list[tuple[str, ast.AST]] = []
        if isinstance(node, ast.Assign):
            for t in node.targets:
                _assign_pairs(t, node.value, pairs)
        elif isinstance(node, ast.AnnAssign):
            _assign_pairs(node.target, node.value, pairs)

        if not pairs:
            return

        scope = self.scope_of(node)
        in_branch = self.in_branch(node)
        for var_name, value in pairs:
            # Evaluate the RHS against live state (it may read the name it rebinds),
            # then strong-update that name's bindings.
            buf = _Bindings()
            self._track_target_value(node, var_name, value, buf)
            key = (scope, var_name)
            self._b.clear_key(key)
            self._b.merge(buf)
            self._label_origin(key, var_name)
            if in_branch:
                # Nothing extra for ``tools`` here: PCL004 already reads the
                # branch flag, and the path merge clears it when both arms
                # bind the name to the same expression.
                self._b.branch.add(key)

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

        # Text the value already is, start to finish. Measured first because
        # every branch below may strong-update the very name this expression
        # reads, and this is the one answer that does not depend on order.
        fully_static = _static_str_len(value)
        if fully_static is not None:
            buf.static_len[key] = fully_static

        # 0. Variable alias: e.g. b = a
        if isinstance(value, ast.Name):
            src = value.id
            origin = self._get(self._b.tainted, src, value)
            if origin:
                buf.tainted[key] = origin
            prefix_origin = self._get(self._b.prefix_tainted, src, value)
            if prefix_origin:
                buf.prefix_tainted[key] = prefix_origin
            if self._has(self._b.sets, src, value):
                buf.sets.add(key)
            if self._has(self._b.set_orderable, src, value):
                buf.set_orderable.add(key)
            static = self._get(self._b.static, src, value)
            if static:
                buf.static[key] = static
            buf.static_len[key] = self.known_static_len(src, value)
            if self._has(self._b.tools_mutated, src, value):
                buf.tools_mutated.add(key)
            if self._has(self._b.branch, src, value):
                buf.branch.add(key)
            if self._has(self._b.json_unsorted, src, value):
                buf.json_unsorted.add(key)
            if self._has(self._b.strings, src, value):
                buf.strings.add(key)
            flows = self._get(self._b.json_flows, src, value)
            if flows:
                buf.json_flows[key] = set(flows)
            lst = self._get(self._b.lists, src, value)
            if lst:
                buf.lists[key] = lst
            dct = self._get(self._b.dicts, src, value)
            if dct:
                buf.dicts[key] = dct
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
            if _elements_orderable(value):
                buf.set_orderable.add(key)
            self._track_json_and_branch(var_name, value, scope, buf)
            return

        # 4. Calls
        if isinstance(value, ast.Call):
            if self._is_set_call(value) or self.returns_set(value):
                buf.sets.add(key)
                if var_name == "tools":
                    buf.tools_mutated.add(key)
                self._track_json_and_branch(var_name, value, scope, buf)
                return

            if self._is_shuffle_call(value):
                buf.tools_mutated.add(key)
                self._track_json_and_branch(var_name, value, scope, buf)
                return

            # Check if list constructed from set: list(my_set) or list(helper())
            if isinstance(value.func, ast.Name) and value.func.id == "list" and value.args:
                arg = value.args[0]
                if (isinstance(arg, ast.Name) and self.is_set_variable(arg.id, arg)) \
                        or isinstance(arg, (ast.Set, ast.SetComp)) \
                        or self.returns_set(arg):
                    buf.tools_mutated.add(key)

            if self.is_json_dumps(value) and not _has_sort_keys(value):
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
        if isinstance(value, ast.Constant) and isinstance(value.value, (str, bytes)):
            # Remembered for hash(): only str/bytes are salted by
            # PYTHONHASHSEED, and the name alone does not say which.
            buf.strings.add(key)
        if isinstance(value, ast.Constant) and isinstance(value.value, str):
            if var_name.isupper():
                buf.static[key] = value.value
            return

        # 7. JoinedStr (f-string) and BinOp (+) string concatenation
        if _is_string_concat(value):
            buf.strings.add(key)
            parts = self._flatten_string_expr(value)
            # How much static text this binding now opens with, so a later
            # `prompt += ...` on the same name is judged against it.
            buf.static_len[key] = self._leading_static_len(parts)
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
            buf.strings.add(key)
            fmt_parts: list[ast.AST] = list(value.args)
            fmt_parts.extend(kw.value for kw in value.keywords if kw.value)
            origin = self.check_sequence_prefix_taint(fmt_parts) if fmt_parts else None
            if origin:
                buf.tainted[key] = origin
                buf.prefix_tainted[key] = origin
            else:
                any_orig = self._find_origin_in_format(value)
                if any_orig:
                    buf.tainted[key] = any_orig
            self._track_json_and_branch(var_name, value, scope, buf)
            return

        # 8b. Conditional expression: either arm can be the value that runs
        if isinstance(value, ast.IfExp):
            for arm in (value.body, value.orelse):
                arm_buf = _Bindings()
                self._track_target_value(node, var_name, arm, arm_buf)
                buf.merge_path(arm_buf)
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
        flows = self._nondeterministic_nodes(value)
        if flows:
            buf.json_flows[key] = flows
        if self._references_branch_var(value):
            buf.branch.add(key)

    def _nondeterministic_nodes(self, node: ast.AST) -> set[int]:
        """Ids of order-unstable expressions that flow into ``node``.

        One store for both rules that carry a mechanical fix: an unsorted
        ``json.dumps`` (PCL002) and a set iterated without ``sorted()``
        (PCL003). Each rule looks up its own node id, so sharing the store
        costs nothing and keeps assignment, aliasing and function returns in
        one place.
        """
        out: set[int] = set()
        for sub in ast.walk(node):
            if self._is_nondeterministic_expr(sub):
                out.add(id(sub))
            elif isinstance(sub, ast.Call) and isinstance(sub.func, ast.Name):
                # A helper's unsorted dumps flows to whoever calls it.
                summary = self._get(self._func_summaries, sub.func.id, sub)
                if summary:
                    out |= set(summary.json_flows)
            elif isinstance(sub, ast.Name):
                flows = self._get(self._b.json_flows, sub.id, sub)
                if flows:
                    out |= set(flows)
        return out

    def _is_nondeterministic_expr(self, sub: ast.AST) -> bool:
        """One expression whose string form can differ between two runs."""
        if isinstance(sub, ast.Call):
            if self.is_json_dumps(sub):
                return not _has_sort_keys(sub)
            return self._is_set_iteration(sub)
        if isinstance(sub, ast.JoinedStr):
            return self._is_set_interpolation(sub)
        return False

    def _is_set_iteration(self, node: ast.Call) -> bool:
        """A ``join``/``str`` that consumes a set without pinning its order."""
        if isinstance(node.func, ast.Attribute) and node.func.attr == "join":
            return bool(node.args) and self.is_unsorted_set_expr(node.args[0])
        if isinstance(node.func, ast.Name) and node.func.id == "str":
            return bool(node.args) and self.is_unsorted_set_expr(node.args[0])
        return False

    def _is_set_interpolation(self, node: ast.JoinedStr) -> bool:
        """An f-string that prints a set directly, e.g. ``f"{tags}"``."""
        return any(
            isinstance(part, ast.FormattedValue)
            and self.is_unsorted_set_expr(part.value)
            for part in node.values
        )

    def _references_branch_var(self, node: ast.AST) -> bool:
        """True when the expression reads a name that is only set on some branches."""
        for sub in ast.walk(node):
            if isinstance(sub, ast.Name) and self._has(self._b.branch, sub.id, sub):
                return True
        return False

    def track_aug_assign(self, node: ast.AugAssign, pass_no: int = 0) -> None:
        """Track augmented assignments like messages += [...] or tools += [...]."""
        if isinstance(node.target, ast.Name):
            scope = self.scope_of(node)
            key = (scope, node.target.id)
            # Marks first: they are idempotent, so they run on every pass and
            # survive the plain Assign a later pass makes to the same name.
            if node.target.id == "tools":
                self._b.tools_mutated.add(key)
            if self.in_branch(node):
                self._b.branch.add(key)
            if _is_string_concat(node.value):
                parts = self._flatten_string_expr(node.value)
                # The target is not an operand of its own `+=`, so what it
                # already holds has to be handed over as text that comes
                # before these parts.
                preceding = self.known_static_len(node.target.id, node)
                origin = self.check_sequence_prefix_taint(parts, preceding)
                if origin:
                    self._b.tainted[key] = origin
                    self._b.prefix_tainted[key] = origin
                    self._label_origin(key, node.target.id)
                elif not pass_no:
                    # First pass only: `preceding` is read back on the next
                    # one, so adding again there would grow the count with
                    # every pass. A plain assignment to the same name re-runs
                    # each pass and re-establishes the base anyway.
                    self._b.static_len[key] = (
                        preceding + self._leading_static_len(parts)
                    )
            if pass_no:
                # Growing the list is not idempotent: running it on every
                # pass would append the elements once per pass.
                return
            current = self._get(self._b.lists, node.target.id, node)
            if current and isinstance(node.value, ast.List):
                self._grow_list(node.target.id, node, node.value.elts)

    def _list_key(self, name: str, node: ast.AST) -> Key | None:
        """The key ``_get`` would resolve ``name`` to, when it holds a list."""
        for key in self._candidates(self._b.lists, name, node, None):
            if key in self._b.lists:
                return key
        return None

    def _grow_list(self, name: str, node: ast.AST, extra: list) -> None:
        """Rebind ``name`` to a longer copy of its list, leaving the tree alone.

        ``_Bindings.copy()`` is shallow: a snapshot taken before this call and
        one taken after it share the same ``ast.List`` object, because both
        still point at the node ``ast.parse`` produced. Editing that node in
        place makes the earlier moment see the later contents, so a call is
        judged by a list append that had not run yet. Copy-on-write gives each
        moment its own node.
        """
        key = self._list_key(name, node)
        if key is None:
            return
        old = self._b.lists[key]
        self._b.lists[key] = ast.copy_location(
            ast.List(elts=[*old.elts, *extra], ctx=old.ctx), old
        )

    def track_expr_stmt(self, node: ast.Expr, pass_no: int = 0) -> None:
        """Track standalone expressions such as random.shuffle(tools) or list.append()."""
        if isinstance(node.value, ast.Call):
            if (self._is_shuffle_call(node.value)
                    and node.value.args and isinstance(node.value.args[0], ast.Name)):
                target = node.value.args[0]
                self.mark_tools_mutated(target.id, target)
                # shuffle() reorders in place, so the name it touches stops
                # having a stable value.
                self._taint_shuffled(target.id, target)
            if isinstance(node.value.func, ast.Attribute):
                attr = node.value.func.attr
                caller = node.value.func.value
                if isinstance(caller, ast.Name):
                    # Marks only from here down. They set flags, so repeating
                    # them is harmless and a later pass's reassignment of the
                    # name cannot leave the flag missing.
                    if attr in ("append", "extend", "insert") \
                            and self._mutation_is_non_deterministic(node):
                        self.mark_tools_mutated(caller.id, caller)
                    if attr == "extend" and node.value.args:
                        arg = node.value.args[0]
                        if isinstance(arg, ast.Name) and self.is_set_variable(arg.id, arg):
                            self.mark_tools_mutated(caller.id, caller)
            if pass_no:
                # Rebuilding the list's contents is not idempotent -- one
                # append per pass would duplicate the element -- so it stays
                # on the first pass only.
                return
            if isinstance(node.value.func, ast.Attribute):
                attr = node.value.func.attr
                caller = node.value.func.value
                if isinstance(caller, ast.Name):
                    if attr == "append" and node.value.args:
                        if self._get(self._b.lists, caller.id, caller):
                            self._grow_list(caller.id, caller,
                                            [node.value.args[0]])
                    elif attr == "extend" and node.value.args:
                        arg = node.value.args[0]
                        if self._get(self._b.lists, caller.id, caller) \
                                and isinstance(arg, ast.List):
                            self._grow_list(caller.id, caller, arg.elts)

    def _taint_shuffled(self, name: str, node: ast.AST) -> None:
        """Record that ``name`` now holds a non-deterministic value."""
        key = (self.scope_of(node), name)
        origin = TaintOrigin(
            variable_name=name, source_call="random.shuffle",
            lineno=getattr(node, "lineno", 0),
        )
        self._b.tainted[key] = origin
        self._b.prefix_tainted[key] = origin

    def _mutation_is_non_deterministic(self, node: ast.AST) -> bool:
        """Whether appending here can change the result between runs.

        A conditional append changes which elements exist. A loop append over
        a list literal, a tuple, or ``range`` visits items in a fixed order
        and so leaves the list exactly as deterministic as it started.
        """
        if self.in_conditional(node):
            return True
        if not self.in_branch(node):
            return False
        return not self._static_loop_iterator(node)

    def _static_loop_iterator(self, node: ast.AST) -> bool:
        """True when the enclosing loop iterates something with fixed order."""
        iterator = self.loop_iterator(node)
        if iterator is None:
            return False
        if isinstance(iterator, (ast.List, ast.Tuple, ast.ListComp)):
            return True
        if isinstance(iterator, ast.Name):
            return self._get(self._b.lists, iterator.id, iterator) is not None
        return (isinstance(iterator, ast.Call)
                and isinstance(iterator.func, ast.Name)
                and iterator.func.id == "range")

    # ------------------------------------------------------------------
    # Function-return taint (one level of inter-procedural flow)
    # ------------------------------------------------------------------

    def build_function_returns(self, tree: ast.AST) -> bool:
        """Resolve the summary each function's ``return`` statements produce.

        Returns True when at least one summary changed. The caller iterates
        until this comes back False: a function declared before its callee
        cannot be resolved until the callee's summary exists, so each pass
        closes one more link of a chain, in either declaration order.
        """
        returns: dict[Scope, list[ast.AST]] = {}
        defs: dict[Scope, list[str]] = {}
        for node in ast.walk(tree):
            if isinstance(node, ast.Return) and node.value is not None:
                returns.setdefault(self.scope_of(node), []).append(node.value)
            elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                defs.setdefault(self.scope_of(node), []).append(node.name)

        changed = False
        for def_scope, names in defs.items():
            for name in names:
                summary = self._summarize_returns(
                    returns.get(def_scope + (name,), ()))
                func_key = (def_scope, name)
                if self._func_summaries.get(func_key) != summary:
                    self._func_summaries[func_key] = summary
                    changed = True
        return changed

    def _summarize_returns(self, values: Iterable[ast.AST]) -> FuncSummary:
        """Fold every ``return`` in one function into a single summary."""
        origin: TaintOrigin | None = None
        is_set = False
        flows: set[int] = set()
        for value in values:
            if origin is None:
                origin = self.get_taint_origin_of_node(value)
            if not is_set:
                is_set = self._value_is_set(value)
            flows |= self._nondeterministic_nodes(value)
        return FuncSummary(origin=origin, is_set=is_set,
                           json_flows=frozenset(flows))

    def _value_is_set(self, value: ast.AST) -> bool:
        if isinstance(value, (ast.Set, ast.SetComp)):
            return True
        if isinstance(value, ast.Call):
            return self._is_set_call(value) or self.returns_set(value)
        if isinstance(value, ast.Name):
            return self.is_set_variable(value.id, value)
        return False

    def returns_set(self, node: ast.AST) -> bool:
        """True when ``node`` is a call whose callee returns a set."""
        if not isinstance(node, ast.Call) or not isinstance(node.func, ast.Name):
            return False
        summary = self._get(self._func_summaries, node.func.id, node)
        return bool(summary and summary.is_set)

    # ------------------------------------------------------------------
    # Call predicates
    # ------------------------------------------------------------------

    def _is_format_call(self, node: ast.Call) -> bool:
        return isinstance(node.func, ast.Attribute) and node.func.attr == "format"

    def _is_join_call(self, node: ast.Call) -> bool:
        return isinstance(node.func, ast.Attribute) and node.func.attr == "join"

    def _find_origin_in_format(self, node: ast.Call) -> TaintOrigin | None:
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
        if not dotted:
            return False
        return self._resolve_parts(dotted.split(".")) == "random.shuffle"

    def _is_file_read(self, node: ast.Call) -> bool:
        return isinstance(node.func, ast.Attribute) and node.func.attr in ("read", "read_text")

    def is_json_dumps(self, node: ast.Call) -> bool:
        """True for ``json.dumps`` however this file imported it.

        orjson and ujson are deliberately left out: their output is just as
        insertion-order dependent, but ``sort_keys=True`` -- the fix PCL002
        attaches -- is not how either of them is asked to sort, so reporting
        them would attach a rewrite that does nothing.
        """
        func = node.func
        if isinstance(func, ast.Attribute) and func.attr == "dumps":
            if isinstance(func.value, ast.Name):
                return (func.value.id in self._json_modules
                        or func.value.id == "json")
            return False
        return isinstance(func, ast.Name) and func.id in self._json_dumps

    def is_unsorted_set_expr(self, expr: ast.AST) -> bool:
        """True when ``expr`` is a set whose iteration order is not pinned."""
        if isinstance(expr, ast.Call):
            if isinstance(expr.func, ast.Name) and expr.func.id == "sorted":
                return False
            if isinstance(expr.func, ast.Name) and expr.func.id == "set":
                return True
        if isinstance(expr, ast.Name):
            return self.is_set_variable(expr.id, expr)
        return isinstance(expr, (ast.Set, ast.SetComp))

    def get_prefix_tainted(self, node: ast.AST) -> TaintOrigin | None:
        """Check if an AST expression is prefix-tainted and return its TaintOrigin."""
        if isinstance(node, (ast.Await, ast.NamedExpr)):
            return self.get_prefix_tainted(node.value)
        if isinstance(node, ast.IfExp):
            # Either arm can be the value that runs, so taint on one is
            # taint. Kept in step with get_taint_origin_of_node, which has
            # always had this branch -- see test_r16j_both_resolvers.
            for arm in (node.body, node.orelse):
                origin = self.get_prefix_tainted(arm)
                if origin:
                    return origin
            return None
        if isinstance(node, ast.Subscript):
            return self._subscript_origin(node)
        if isinstance(node, ast.Name):
            origin = self._get(self._b.prefix_tainted, node.id, node)
            return origin if origin else None
        if _is_string_concat(node):
            parts = self._flatten_string_expr(node)
            return self.check_sequence_prefix_taint(parts)
        if isinstance(node, ast.Call):
            origin = self.is_taint_source(node)
            if origin:
                return origin
            if isinstance(node.func, ast.Name):
                summary = self._get(self._func_summaries, node.func.id, node)
                if summary and summary.origin:
                    return summary.origin
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
        if isinstance(node, ast.UnaryOp):
            return self.get_prefix_tainted(node.operand)
        if isinstance(node, ast.BinOp) and not isinstance(node.op, ast.Add):
            # Kept in step with get_taint_origin_of_node: the two decide the
            # same question and must not drift apart (see R-16j).
            for operand in (node.left, node.right):
                origin = self.get_prefix_tainted(operand)
                if origin:
                    return origin
        return None

    def is_tainted_variable(self, var_name: str, node: ast.AST | None = None) -> bool:
        return self._has(self._b.tainted, var_name, node)

    def is_set_variable(self, var_name: str, node: ast.AST | None = None) -> bool:
        return self._has(self._b.sets, var_name, node)

    def is_set_orderable(self, var_name: str, node: ast.AST | None = None) -> bool:
        """True only when every arm bound this name to a provably sortable set."""
        return self._has(self._b.set_orderable, var_name, node)

    def is_orderable_set_expr(self, node: ast.AST) -> bool:
        """True when wrapping ``node`` in ``sorted()`` cannot raise.

        This is the gate on the PCL003 autofix: reporting the finding is
        always right, shipping ``sorted(...)`` is not, unless the elements
        are visible and mutually comparable.
        """
        if isinstance(node, ast.Set):
            return _elements_orderable(node)
        if isinstance(node, ast.Name):
            return self._has(self._b.set_orderable, node.id, node)
        return False

    def is_tools_mutated(self, var_name: str, node: ast.AST | None = None) -> bool:
        return self._has(self._b.tools_mutated, var_name, node)

    def is_json_unsorted(self, var_name: str, node: ast.AST | None = None) -> bool:
        return self._has(self._b.json_unsorted, var_name, node)

    def is_branch_var(self, var_name: str, node: ast.AST | None = None) -> bool:
        return self._has(self._b.branch, var_name, node)
