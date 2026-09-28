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

# Every rule this engine can emit. Selectors and disable comments are validated
# against it so a typo can never silently switch a rule off (or on).
KNOWN_RULE_IDS: frozenset = frozenset({"PCL001", "PCL002", "PCL003", "PCL004"})

# One-line catalog used by machine-readable output (SARIF). The full message
# and fix text live on each Diagnostic; this is what a rule list shows before
# any finding exists.
RULE_SHORT_DESCRIPTIONS: dict[str, str] = {
    "PCL001": "Dynamic value placed before static prompt text, invalidating the cached prefix",
    "PCL002": "json.dumps() without sort_keys=True reaching a prompt",
    "PCL003": "Unsorted set iterated while building prompt text",
    "PCL004": "tools list assembled or mutated in a non-deterministic order",
}


def _end_pos(node: ast.AST) -> tuple[int, int] | None:
    """``(line, byte_col)`` just past ``node``, when ast recorded one."""
    line = getattr(node, "end_lineno", None)
    col = getattr(node, "end_col_offset", None)
    if line is None or col is None:
        return None
    return line, col


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

    def prepare(self, tree: ast.AST) -> None:
        """Pre-scan AST to collect what reaches an LLM API call."""
        self._llm_used_vars = set()
        self._nodes_in_llm_sink = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and self._is_llm_api_call(node):
                for child in ast.walk(node):
                    self._nodes_in_llm_sink.add(id(child))
                    if isinstance(child, ast.Name):
                        self._llm_used_vars.add(child.id)

    def run(self, tree: ast.AST, file_path: str = "") -> list[Diagnostic]:
        """Run every rule over ``tree`` and return its diagnostics."""
        self._file_path = file_path
        self._diagnostics = []
        self.prepare(tree)
        for node in ast.walk(tree):
            self.check_node(node)
        return self._diagnostics

    def _add(self, lineno: int, col_offset: int, rule_id: str, rule_name: str,
             message: str, fix_suggestion: str, severity: str,
             edits: tuple[TextEdit, ...] = ()) -> None:
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
        self._check_pcl002(node)
        self._check_pcl003(node)
        self._check_pcl004(node)

    def _is_llm_api_call(self, node: ast.Call) -> bool:
        func = node.func
        if isinstance(func, ast.Attribute):
            # Innermost-first: parts[0] is the method, parts[1] the resource
            # it hangs off. Both must match exactly. Substring matching used
            # to accept `db.messages.create_index` and `x.completions.recreate`
            # while missing `chat.completions.parse`, which never contains
            # "create" at all.
            parts: list[str] = []
            current: ast.expr = func
            while isinstance(current, ast.Attribute):
                parts.append(current.attr)
                current = current.value
            if (len(parts) >= 2
                    and parts[0] in _SINK_METHODS
                    and parts[1] in _SINK_RESOURCES):
                return True
        # No keyword fallback. ``messages=`` plus ``model=`` is what any local
        # ``def render(messages, model)`` looks like, and treating it as a sink
        # means judging a plain helper's arguments as prompt prefixes. The SDK
        # shapes above cover Anthropic, OpenAI chat and OpenAI responses; a
        # bespoke wrapper is a name this linter cannot know.
        return False

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
        return self._keyword_node(node, "system")

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
            fix_suggestion=f"Move dynamic value '{origin.source_call}' to the end of the static prompt or into the final user message to preserve prefix cache hits.",
            severity="ERROR",
        )

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
        self._check_pcl001_system(node)
        self._check_pcl001_messages(node)

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

        for idx, msg_node in enumerate(msg_elts):
            resolved_dict = self._resolve_dict_node(msg_node)
            if not resolved_dict:
                continue
            is_prefix = (self._is_system_message(resolved_dict) or idx == 0
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
                message="json.dumps() called without sort_keys=True",
                fix_suggestion="Pass 'sort_keys=True' to 'json.dumps(...)' to guarantee deterministic key serialization across requests.",
                severity="WARNING",
                edits=self._pcl002_edits(node),
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
        node_id = id(node)
        for (_scope, name), flows in self.tracker.json_flows.items():
            if node_id not in flows:
                continue
            if name in self._llm_used_vars or self._is_prompt_name(name):
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
        if not self._reaches_prompt(node):
            return
        # Check join calls: "...".join(tag_set)
        if isinstance(node, ast.Call):
            if (isinstance(node.func, ast.Attribute) and node.func.attr == "join"
                    and node.args and self._is_unsorted_set_expr(node.args[0])):
                self._add(
                    lineno=node.lineno,
                    col_offset=node.col_offset,
                    rule_id="PCL003",
                    rule_name="set-iteration-in-prompt",
                    message="Set iterated in join() without sorted() - iteration order is non-deterministic",
                    fix_suggestion=self._pcl003_fix(),
                    severity="ERROR",
                    edits=self._pcl003_edits_for(node.args[0]),
                )
                return
            # Check str(tag_set)
            if (isinstance(node.func, ast.Name) and node.func.id == "str"
                    and node.args and self._is_unsorted_set_expr(node.args[0])):
                self._add(
                    lineno=node.lineno,
                    col_offset=node.col_offset,
                    rule_id="PCL003",
                    rule_name="set-iteration-in-prompt",
                    message="Set converted to string without sorted() - iteration order is non-deterministic",
                    fix_suggestion=self._pcl003_fix(),
                    severity="ERROR",
                    edits=self._pcl003_edits_for(node.args[0]),
                )
                return

        # Check f-string interpolation: f"{tag_set}"
        if isinstance(node, ast.JoinedStr):
            for part in node.values:
                if isinstance(part, ast.FormattedValue) and self._is_unsorted_set_expr(part.value):
                    self._add(
                        lineno=getattr(part, "lineno", node.lineno),
                        col_offset=getattr(part, "col_offset", node.col_offset),
                        rule_id="PCL003",
                        rule_name="set-iteration-in-prompt",
                        message="Set interpolated in f-string without sorted() - iteration order is non-deterministic",
                        fix_suggestion=self._pcl003_fix(),
                        severity="ERROR",
                        edits=self._pcl003_edits_for(part.value),
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
                )
