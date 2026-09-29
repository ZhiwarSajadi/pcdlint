"""The 4 core detection rules for pcdlint."""

import ast
from collections.abc import Sequence

from pcdlint.models import Diagnostic, TaintOrigin, TextEdit
from pcdlint.taint import TaintTracker

# Substrings that mark an assignment target as prompt/LLM-prefix material.
PROMPT_NAME_KEYWORDS = ("prompt", "system", "prefix", "instruction", "rules", "context")

# The terminal method and the resource it hangs off for every documented
# Anthropic and OpenAI entry point -- create, the structured-output parse
# variants, and the streaming variants. Matched as exact names, so
# `beta.messages.create` counts and `messages_repo.create_user` does not.
# Deliberately absent: `messages.count_tokens`, which never starts a
# completion and so never invalidates a cache prefix.
_SINK_METHODS = frozenset({"create", "parse", "stream"})
_SINK_RESOURCES = frozenset({"completions", "messages", "responses"})

# Keywords that make ``.messages.create(...)`` a completion rather than a
# message send: a model to run, or the payload the model reads. ``tools`` is
# here because PCL004 exists to judge it and nothing else.
_LLM_SHAPE_KEYWORDS = frozenset({
    "model", "messages", "input", "system", "instructions", "prompt", "tools",
})

# SDK packages whose import alone says this file writes prompts. Used only to
# decide whether a prompt-shaped *name* means anything; a name that reaches a
# real sink is proof regardless and never consults this.
_LLM_SDK_MODULES = frozenset({"anthropic", "openai", "litellm"})


def _root_module(name: str) -> str:
    """``anthropic.resources`` -> ``anthropic``, so `from x.y import z` matches."""
    return name.split(".", 1)[0]


def call_parts(node: ast.Call) -> list[str]:
    """Attribute chain of ``node.func``, outermost attribute first."""
    parts: list[str] = []
    current: ast.expr = node.func
    while isinstance(current, ast.Attribute):
        parts.append(current.attr)
        current = current.value
    return parts


def is_llm_api_call(node: ast.Call) -> bool:
    """True for a documented Anthropic or OpenAI entry point.

    Both halves of the path must match exactly. Substring matching used to
    accept ``db.messages.create_index`` and ``x.completions.recreate`` while
    missing ``chat.completions.parse``, which never contains "create" at all.

    The path alone is still not enough: ``twilio.messages.create(body=...)``
    is the same two words and sends a text message. Every completion entry
    point takes a model or a prompt payload, so the call has to carry one --
    or use the legacy positional ``create(model, messages)`` form, which has
    no keywords at all. This only ever narrows what counts as a sink; there
    is deliberately no fallback that accepts a bare ``messages=`` plus
    ``model=`` pair, because that is what any local ``def render(messages,
    model)`` looks like. A bespoke wrapper is a name this linter cannot know.
    """
    parts = call_parts(node)
    if len(parts) < 2 or parts[0] not in _SINK_METHODS \
            or parts[1] not in _SINK_RESOURCES:
        return False
    if len(node.args) >= 2:
        return True
    return any(kw.arg in _LLM_SHAPE_KEYWORDS for kw in node.keywords)


def is_anthropic_sink(node: ast.Call) -> bool:
    """True for the Anthropic ``messages`` resource (create/stream/beta)."""
    parts = call_parts(node)
    return len(parts) >= 2 and parts[1] == "messages"

# Every rule this engine can emit. Selectors and disable comments are validated
# against it so a typo can never silently switch a rule off (or on).
KNOWN_RULE_IDS: frozenset = frozenset(
    {"PCL001", "PCL002", "PCL003", "PCL004", "PCL005"}
)

# One-line catalog used by machine-readable output (SARIF). The full message
# and fix text live on each Diagnostic; this is what a rule list shows before
# any finding exists.
RULE_SHORT_DESCRIPTIONS: dict[str, str] = {
    "PCL001": "Dynamic value placed before static prompt text, invalidating the cached prefix",
    "PCL002": "json.dumps() without sort_keys=True reaching a prompt",
    "PCL003": "Unsorted set iterated while building prompt text",
    "PCL004": "tools list assembled or mutated in a non-deterministic order",
    "PCL005": "Dynamic value before a cache_control breakpoint, a total miss on Anthropic",
}

# Severity each rule is reported at. Kept beside the catalog so SARIF's
# defaultConfiguration -- which a consumer reads before any finding exists --
# cannot disagree with what the engine emits.
RULE_SEVERITIES: dict[str, str] = {
    "PCL001": "ERROR",
    "PCL002": "WARNING",
    "PCL003": "ERROR",
    "PCL004": "WARNING",
    "PCL005": "ERROR",
}


def _end_pos(node: ast.AST) -> tuple[int, int] | None:
    """``(line, byte_col)`` just past ``node``, when ast recorded one."""
    line = getattr(node, "end_lineno", None)
    col = getattr(node, "end_col_offset", None)
    if line is None or col is None:
        return None
    return line, col


def _end_of(*nodes: ast.AST | None) -> tuple[int, int] | None:
    """Span end from the same node :meth:`RuleEngine._line_of` would pick."""
    for node in nodes:
        if node is not None and hasattr(node, "lineno"):
            span_end = _end_pos(node)
            if span_end is not None:
                return span_end
            return getattr(node, "lineno", 1), getattr(node, "col_offset", 0)
    return None


def _insert_before(node: ast.expr, text: str) -> TextEdit | None:
    return TextEdit(node.lineno, node.col_offset, node.lineno, node.col_offset, text)


def _insert_after(node: ast.AST, text: str) -> TextEdit | None:
    end = _end_pos(node)
    if end is None:
        return None
    return TextEdit(end[0], end[1], end[0], end[1], text)


def _replace(node: ast.expr, text: str) -> TextEdit | None:
    end = _end_pos(node)
    if end is None:
        return None
    return TextEdit(node.lineno, node.col_offset, end[0], end[1], text)


class RuleEngine:
    """Applies all 4 lint rules against analyzed code."""

    def __init__(self, tracker: TaintTracker) -> None:
        self.tracker = tracker
        self._diagnostics: list[Diagnostic] = []
        self._file_path: str = ""
        self._llm_used_vars: set = set()
        # Every node syntactically inside an LLM sink call. An expression
        # here is a payload by construction, which is what lets PCL002 and
        # PCL003 fire on a json.dumps()/join() passed inline instead of only
        # on one that went through a variable.
        self._nodes_in_llm_sink: set[int] = set()
        # Reverse index over tracker.json_flows, filled by prepare().
        self._flow_names: dict[int, set] = {}
        # The sink currently being judged, so a fix suggestion can speak to
        # the provider it belongs to.
        self._sink: ast.Call | None = None

    def prepare(self, tree: ast.AST) -> None:
        """Pre-scan AST to collect what reaches an LLM API call."""
        self._llm_used_vars = set()
        self._nodes_in_llm_sink = set()
        self._flow_names = {}
        # Whether this file deals with an LLM at all. Without evidence, a
        # name that merely *looks* like prompt material -- `context`,
        # `rules`, `system_info` -- is just a name, and PCL003's autofix
        # would rewrite ordinary data code on that guess.
        self._llm_context = False
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and self._is_llm_api_call(node):
                self._llm_context = True
                for child in ast.walk(node):
                    self._nodes_in_llm_sink.add(id(child))
                    if isinstance(child, ast.Name):
                        self._llm_used_vars.add(child.id)
            elif isinstance(node, ast.Import):
                if any(_root_module(alias.name) in _LLM_SDK_MODULES
                       for alias in node.names):
                    self._llm_context = True
            elif isinstance(node, ast.ImportFrom):
                if _root_module(node.module or "") in _LLM_SDK_MODULES:
                    self._llm_context = True
        # Reverse index: node id -> the names bound to it. Building it once
        # turns _reaches_prompt's scan of every flow entry into a lookup, so
        # the per-node cost no longer grows with the flow table.
        for (_scope, name), flows in self.tracker.json_flows.items():
            for node_id in flows:
                self._flow_names.setdefault(node_id, set()).add(name)

    def run(self, tree: ast.AST, file_path: str = "") -> list[Diagnostic]:
        """Run every rule over ``tree`` and return its diagnostics."""
        self._file_path = file_path
        self._diagnostics = []
        self.prepare(tree)
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                # Judge the call against the bindings it ran with. Tracking
                # covers the whole file before any rule sees it, so without
                # this a name rebound after the call would be read as its
                # argument.
                with self.tracker.at(node):
                    self.check_node(node)
            else:
                self.check_node(node)
        return self._diagnostics

    def _add(self, lineno: int, col_offset: int, rule_id: str, rule_name: str,
             message: str, fix_suggestion: str, severity: str,
             edits: tuple[TextEdit, ...] = (),
             end: tuple[int, int] | None = None) -> None:
        self._diagnostics.append(Diagnostic(
            file_path=self._file_path,
            lineno=lineno,
            col_offset=col_offset,
            rule_id=rule_id,
            rule_name=rule_name,
            message=message,
            fix_suggestion=fix_suggestion,
            severity=severity,
            edits=edits,
            end_lineno=end[0] if end is not None else None,
            end_col_offset=end[1] if end is not None else None,
        ))

    @staticmethod
    def _line_of(*nodes: ast.AST | None) -> int:
        for node in nodes:
            if node is not None and hasattr(node, "lineno"):
                return node.lineno
        return 1

    @staticmethod
    def _col_of(*nodes: ast.AST | None) -> int:
        for node in nodes:
            if node is not None and hasattr(node, "col_offset"):
                return node.col_offset
        return 0

    def check_node(self, node: ast.AST) -> None:
        self._check_pcl001(node)
        self._check_pcl005(node)
        self._check_pcl002(node)
        self._check_pcl003(node)
        self._check_pcl004(node)

    @staticmethod
    def _is_llm_api_call(node: ast.Call) -> bool:
        return is_llm_api_call(node)

    @staticmethod
    def _is_anthropic_sink(node: ast.Call) -> bool:
        return is_anthropic_sink(node)
    @staticmethod
    def _keyword_node(node: ast.Call, name: str) -> ast.AST | None:
        for kw in node.keywords:
            if kw.arg == name:
                return kw.value
        return None

    @staticmethod
    def _is_prompt_name(name: str) -> bool:
        lowered = name.lower()
        return any(keyword in lowered for keyword in PROMPT_NAME_KEYWORDS)

    # --- argument resolution ---

    def _get_system_arg(self, node: ast.Call) -> ast.AST | None:
        # instructions= is the Responses API's spelling of system=: the same
        # prefix role, so it must be judged by the same rule.
        found = self._keyword_node(node, "system")
        if found is not None:
            return found
        return self._keyword_node(node, "instructions")

    def _get_messages_arg(self, node: ast.Call) -> ast.AST | None:
        for name in ("messages", "input"):
            value = self._keyword_node(node, name)
            if value is not None:
                return value
        # Legacy positional form: create(model, messages, ...)
        if len(node.args) >= 2:
            return node.args[1]
        return None

    def _get_tools_arg(self, node: ast.Call) -> ast.AST | None:
        return self._keyword_node(node, "tools")

    def _resolve_dict_node(self, node: ast.AST) -> ast.Dict | None:
        return self.tracker.resolve_dict(node)

    def _resolve_list_node(self, node: ast.AST) -> ast.List | None:
        return self.tracker.resolve_list(node)

    def _is_system_message(self, msg: ast.Dict) -> bool:
        for key, val in zip(msg.keys, msg.values):
            if (isinstance(key, ast.Constant) and key.value == "role"
                    and isinstance(val, ast.Constant)
                    and val.value in ("system", "developer")):
                return True
        return False

    def _has_cache_control(self, node: ast.AST) -> bool:
        for sub in ast.walk(node):
            if isinstance(sub, ast.Constant) and sub.value == "cache_control":
                return True
        return False

    # --- PCL001: prefix-taint-injection ---

    def _report_pcl001(self, value: ast.AST, origin: TaintOrigin, context: str,
                       *fallbacks: ast.AST | None) -> None:
        self._add(
            lineno=self._line_of(value, *fallbacks),
            col_offset=self._col_of(value, *fallbacks),
            rule_id="PCL001",
            rule_name="prefix-taint-injection",
            message=f"Prefix taint detected: '{origin.source_call}' {context}",
            fix_suggestion=self._prefix_fix(origin.source_call),
            severity="ERROR",
            end=_end_of(value, *fallbacks),
        )

    def _prefix_fix(self, source_call: str) -> str:
        """Where to move the value, phrased for the provider being called.

        OpenAI caches the longest matching prefix, so the dynamic value
        belongs at the end. Anthropic only hits when every byte up to a
        cache_control breakpoint is identical, so it belongs after one.
        """
        if self._sink is not None and self._is_anthropic_sink(self._sink):
            return (f"Move the dynamic value '{source_call}' into a content "
                    "block after the last cache_control breakpoint, or into "
                    "the final user message.")
        return (f"Move dynamic value '{source_call}' to the end of the static "
                "prompt or into the final user message to preserve prefix "
                "cache hits.")

    def _report_first_taint(self, values: Sequence[ast.AST], context: str,
                            *fallbacks: ast.AST | None) -> bool:
        """Report the first prefix-tainted value in ``values``; True when one was found."""
        for value in values:
            origin = self.tracker.get_prefix_tainted(value)
            if origin:
                self._report_pcl001(value, origin, context, *fallbacks)
                return True
        return False

    def _check_pcl001(self, node: ast.AST) -> None:
        if not isinstance(node, ast.Call):
            return
        if not self._is_llm_api_call(node):
            return
        self._sink = node
        self._check_pcl001_system(node)
        self._check_pcl001_messages(node)

    # --- PCL005: taint-before-cache-breakpoint ---

    @staticmethod
    def _blocks_of(value: ast.AST | None) -> list[ast.AST]:
        """The content blocks of a list-shaped argument, or the scalar itself."""
        if value is None:
            return []
        if isinstance(value, ast.List):
            return list(value.elts)
        return [value]

    def _cache_units(self, node: ast.Call) -> list[tuple[list, ast.AST]]:
        """Every system block and message in prompt order, as (values, carrier).

        ``values`` is what gets read for taint; ``carrier`` is the node a
        cache_control breakpoint can sit on.
        """
        units: list[tuple[list, ast.AST]] = []
        for argument in (self._get_system_arg(node), self._get_messages_arg(node)):
            for block in self._blocks_of(argument):
                resolved = (self._resolve_list_node(block)
                            if isinstance(block, ast.Name) else None)
                for item in (resolved.elts if resolved else [block]):
                    inner = self._resolve_dict_node(item)
                    if inner is not None:
                        units.append((list(inner.values), inner))
                    else:
                        units.append(([item], item))
        return units

    def _check_pcl005(self, node: ast.AST) -> None:
        """Anthropic's cache is all-or-nothing up to the last breakpoint.

        OpenAI keeps the longest matching prefix, so a dynamic value at the
        end still earns partial hits and PCL001's "static first" ordering
        says enough. Anthropic hits only when every byte up to a
        cache_control breakpoint is identical: the same code is a 100% miss
        there, and PCL001 never reports it because the static text comes
        first.
        """
        if not isinstance(node, ast.Call):
            return
        if not self._is_llm_api_call(node):
            return
        if not self._is_anthropic_sink(node):
            return
        units = self._cache_units(node)
        last_breakpoint = -1
        for index, (_values, carrier) in enumerate(units):
            if self._has_cache_control(carrier):
                last_breakpoint = index
        if last_breakpoint < 0:
            return
        for values, _carrier in units[:last_breakpoint + 1]:
            for value in values:
                origin = self.tracker.get_taint_origin_of_node(value)
                if origin is None:
                    continue
                self._add(
                    lineno=self._line_of(value, node),
                    col_offset=self._col_of(value, node),
                    rule_id="PCL005",
                    rule_name="taint-before-cache-breakpoint",
                    message=(f"Prefix taint detected: '{origin.source_call}' "
                             "before a cache_control breakpoint, a total miss"),
                    fix_suggestion=(
                        "Move the dynamic value into a content block after "
                        "the last cache_control breakpoint, or into the "
                        "final user message."),
                    severity="ERROR",
                    end=_end_of(value, node),
                )
                return

    def _check_pcl001_system(self, node: ast.Call) -> None:
        system_val = self._get_system_arg(node)
        if system_val is None:
            return
        context = "in system prompt"

        # System can be a list of content blocks (Anthropic)
        if isinstance(system_val, ast.List):
            for block in system_val.elts:
                resolved = self._resolve_dict_node(block)
                if resolved and self._report_first_taint(resolved.values, context, node, block):
                    return
            return

        if isinstance(system_val, ast.Name):
            blocks = self._resolve_list_node(system_val)
            if blocks is not None:
                for block in blocks.elts:
                    resolved = self._resolve_dict_node(block)
                    if resolved and self._report_first_taint(resolved.values, context, node, block):
                        return
                return

        self._report_first_taint([system_val], context, node)

    def _check_pcl001_messages(self, node: ast.Call) -> None:
        messages_val = self._get_messages_arg(node)
        if messages_val is None:
            return
        msg_elts: list[ast.expr] = []
        if isinstance(messages_val, ast.List):
            msg_elts = messages_val.elts
        else:
            msgs = self._resolve_list_node(messages_val)
            if msgs is not None:
                msg_elts = msgs.elts
            else:
                # Scalar payload (Responses API ``input="..."`` or a prompt
                # string bound to a variable): the whole value is the prefix.
                self._report_first_taint([messages_val], "in message prefix", node)
                return

        # Find last index with cache_control
        last_cache_idx = -1
        for idx, msg_node in enumerate(msg_elts):
            resolved = self._resolve_dict_node(msg_node)
            if resolved and self._has_cache_control(resolved):
                last_cache_idx = idx

        # With a separate system=/instructions= argument the string does not
        # start at messages[0]: that message is the first *turn*, and the
        # README tells users to put dynamic values there. Without one it is
        # the whole prompt, so it is the prefix.
        separate_system = self._get_system_arg(node) is not None

        for idx, msg_node in enumerate(msg_elts):
            resolved_dict = self._resolve_dict_node(msg_node)
            if not resolved_dict:
                continue
            is_prefix = ((idx == 0 and not separate_system)
                         or self._is_system_message(resolved_dict)
                         or self._has_cache_control(resolved_dict)
                         or (last_cache_idx != -1 and idx <= last_cache_idx))
            if not is_prefix:
                continue
            if self._report_message_taint(resolved_dict, node):
                break

    def _report_message_taint(self, msg: ast.Dict, call: ast.Call) -> bool:
        """Report the first prefix taint in one message dict; True when found."""
        for val in msg.values:
            if isinstance(val, ast.List):
                for sub in val.elts:
                    sub_dict = self._resolve_dict_node(sub)
                    if sub_dict and self._report_first_taint(
                            sub_dict.values, "in message prefix", call, msg, sub):
                        return True
            elif self._report_first_taint([val], "in message prefix", call, msg):
                return True
        return False

    # --- PCL002: unsorted-json-in-prefix ---

    def _check_pcl002(self, node: ast.AST) -> None:
        if not isinstance(node, ast.Call):
            return
        if not self._is_json_dumps(node):
            return
        if self._has_sort_keys_arg(node):
            return
        if self._reaches_prompt(node):
            self._add(
                lineno=node.lineno,
                col_offset=node.col_offset,
                rule_id="PCL002",
                rule_name="unsorted-json-in-prefix",
                message="json.dumps() without sort_keys=True: dict key order "
                        "depends on how the dict was built",
                fix_suggestion="Pass 'sort_keys=True' to 'json.dumps(...)' to make the "
                               "key order deterministic however the dict was built "
                               "(merged dicts, sets, DB rows, ** spreads).",
                severity="WARNING",
                edits=self._pcl002_edits(node),
                end=_end_pos(node),
            )

    @staticmethod
    def _pcl002_edits(node: ast.Call) -> tuple:
        """A rewrite that adds sort_keys=True without ever duplicating it."""
        if any(kw.arg is None for kw in node.keywords):
            # A **kwargs splat may already carry sort_keys. Appending a second
            # one still parses -- so the post-fix ast.parse guard misses it --
            # and raises TypeError: got multiple values for keyword argument
            # as soon as opts happens to define that key. Report the finding,
            # decline the rewrite; only a human knows what is in opts.
            return ()
        sort_kw = next((kw for kw in node.keywords if kw.arg == "sort_keys"), None)
        if sort_kw is not None and sort_kw.value is not None:
            edit = _replace(sort_kw.value, "True")
            return (edit,) if edit else ()
        if not node.args and not node.keywords:
            # No argument to follow and no comma to lead with, so the keyword
            # goes straight before the closing paren.
            end = _end_pos(node)
            if end is None:
                return ()
            line, col = end
            return (TextEdit(line, col - 1, line, col - 1, "sort_keys=True"),)
        # Anchoring after the last argument keeps a trailing comma valid:
        # ``json.dumps(x,)`` becomes ``json.dumps(x, sort_keys=True,)``.
        anchor = node.keywords[-1].value if node.keywords else node.args[-1]
        edit = _insert_after(anchor, ", sort_keys=True")
        return (edit,) if edit else ()

    @staticmethod
    def _has_sort_keys_arg(node: ast.Call) -> bool:
        for kw in node.keywords:
            if (kw.arg == "sort_keys"
                    and isinstance(kw.value, ast.Constant) and kw.value.value is True):
                return True
        return False

    def _reaches_prompt(self, node: ast.AST) -> bool:
        """True when this expression is, or is bound into, a prompt payload.

        Two ways in: written inline inside an LLM call, or assigned to a name
        that either reaches one or is spelled like prompt material. Shared by
        PCL002 and PCL003 so neither can fire on code that never reaches a
        prompt -- and neither can miss one that does, just written inline.
        """
        if id(node) in self._nodes_in_llm_sink:
            return True
        for name in self._flow_names.get(id(node), ()):
            # Reaching a sink is proof whatever its name is. A prompt-shaped
            # name is only a guess, and a guess is worth nothing in a file
            # that never mentions an LLM.
            if name in self._llm_used_vars:
                return True
            if self._llm_context and self._is_prompt_name(name):
                return True
        return False

    def _is_json_dumps(self, node: ast.Call) -> bool:
        """Delegated so the rule and the tracker can never disagree."""
        return self.tracker.is_json_dumps(node)

    # --- PCL003: set-iteration-in-prompt ---

    def _is_unsorted_set_expr(self, expr: ast.AST) -> bool:
        """Delegated so the rule and the flow collector can never disagree."""
        return self.tracker.is_unsorted_set_expr(expr)

    @staticmethod
    def _pcl003_fix() -> str:
        return ("Wrap the set in 'sorted(...)' before string conversion; "
                "Python's PYTHONHASHSEED randomizes set iteration order across processes.")

    @staticmethod
    def _pcl003_edits(argument: ast.expr | None) -> tuple:
        """Wrap ``argument`` in ``sorted(...)`` as two insertions around it."""
        if argument is None:
            return ()
        opening = _insert_before(argument, "sorted(")
        closing = _insert_after(argument, ")")
        return tuple(e for e in (opening, closing) if e is not None)

    def _pcl003_edits_for(self, argument: ast.expr | None) -> tuple:
        """Fix edits, or nothing when ``sorted()`` could raise on the value.

        The finding still stands either way: declining the rewrite is what
        keeps ``--fix`` from replacing a working ``", ".join({1, "a"})`` with
        a TypeError at runtime.
        """
        if argument is None or not self.tracker.is_orderable_set_expr(argument):
            return ()
        return self._pcl003_edits(argument)

    def _check_pcl003(self, node: ast.AST) -> None:
        # PCL003 is named for prompts and is an ERROR with an autofix. A set
        # joined into a log line or a dict key does not touch the prompt
        # cache, so gating on reachability is what keeps it from failing
        # builds over code it has no business judging.
        #
        # Each match tests reachability *last*: it is the expensive half, and
        # it used to run on every node in the file regardless of shape.
        # Check join calls: "...".join(tag_set)
        if isinstance(node, ast.Call):
            if (isinstance(node.func, ast.Attribute) and node.func.attr == "join"
                    and node.args and self._is_unsorted_set_expr(node.args[0])
                    and self._reaches_prompt(node)):
                self._add(
                    lineno=node.lineno,
                    col_offset=node.col_offset,
                    rule_id="PCL003",
                    rule_name="set-iteration-in-prompt",
                    message="Set iterated in join() without sorted() - iteration order is non-deterministic",
                    fix_suggestion=self._pcl003_fix(),
                    severity="ERROR",
                    edits=self._pcl003_edits_for(node.args[0]),
                    end=_end_pos(node),
                )
                return
            # Check str(tag_set)
            if (isinstance(node.func, ast.Name) and node.func.id == "str"
                    and node.args and self._is_unsorted_set_expr(node.args[0])
                    and self._reaches_prompt(node)):
                self._add(
                    lineno=node.lineno,
                    col_offset=node.col_offset,
                    rule_id="PCL003",
                    rule_name="set-iteration-in-prompt",
                    message="Set converted to string without sorted() - iteration order is non-deterministic",
                    fix_suggestion=self._pcl003_fix(),
                    severity="ERROR",
                    edits=self._pcl003_edits_for(node.args[0]),
                    end=_end_pos(node),
                )
                return

        # Check f-string interpolation: f"{tag_set}"
        if isinstance(node, ast.JoinedStr):
            for part in node.values:
                if (isinstance(part, ast.FormattedValue)
                        and self._is_unsorted_set_expr(part.value)
                        and self._reaches_prompt(node)):
                    self._add(
                        lineno=getattr(part, "lineno", node.lineno),
                        col_offset=getattr(part, "col_offset", node.col_offset),
                        rule_id="PCL003",
                        rule_name="set-iteration-in-prompt",
                        message="Set interpolated in f-string without sorted() - iteration order is non-deterministic",
                        fix_suggestion=self._pcl003_fix(),
                        severity="ERROR",
                        edits=self._pcl003_edits_for(part.value),
                        end=_end_pos(part),
                    )
                    return

    # --- PCL004: dynamic-tools-mutation ---

    @staticmethod
    def _pcl004_fix() -> str:
        return ("Keep the 'tools' list order strictly static and deterministic; "
                "changing tool order invalidates the entire prompt cache hierarchy.")

    def _check_pcl004(self, node: ast.AST) -> None:
        if not isinstance(node, ast.Call):
            return
        if not self._is_llm_api_call(node):
            return
        tools_var = self._get_tools_arg(node)
        if tools_var is None:
            return
        if isinstance(tools_var, ast.Name):
            var_name = tools_var.id
            if (self.tracker.is_tainted_variable(var_name, tools_var)
                    or self.tracker.is_tools_mutated(var_name, tools_var)
                    or self.tracker.is_set_variable(var_name, tools_var)
                    or self.tracker.is_branch_var(var_name, tools_var)):
                self._add(
                    lineno=tools_var.lineno,
                    col_offset=tools_var.col_offset,
                    rule_id="PCL004",
                    rule_name="dynamic-tools-mutation",
                    message=f"Tools list '{var_name}' may have been dynamically mutated",
                    fix_suggestion=self._pcl004_fix(),
                    severity="WARNING",
                    end=_end_pos(tools_var),
                )
        elif isinstance(tools_var, (ast.Set, ast.SetComp)):
            self._add(
                lineno=getattr(tools_var, "lineno", node.lineno),
                col_offset=getattr(tools_var, "col_offset", 0),
                rule_id="PCL004",
                rule_name="dynamic-tools-mutation",
                message="Tools list passed as set with non-deterministic order",
                fix_suggestion=self._pcl004_fix(),
                severity="WARNING",
                end=_end_pos(tools_var),
            )
        elif isinstance(tools_var, ast.Call) and isinstance(tools_var.func, ast.Name) \
                and tools_var.func.id == "list" and tools_var.args:
            arg = tools_var.args[0]
            if (isinstance(arg, ast.Name) and self.tracker.is_set_variable(arg.id, arg)) \
                    or isinstance(arg, (ast.Set, ast.SetComp)) \
                    or self.tracker.returns_set(arg):
                self._add(
                    lineno=tools_var.lineno,
                    col_offset=tools_var.col_offset,
                    rule_id="PCL004",
                    rule_name="dynamic-tools-mutation",
                    message="Tools list constructed from set without deterministic ordering",
                    fix_suggestion=self._pcl004_fix(),
                    severity="WARNING",
                    end=_end_pos(tools_var),
                )
