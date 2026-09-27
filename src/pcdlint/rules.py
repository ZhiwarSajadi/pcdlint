"""The 4 core detection rules for pcdlint."""

import ast
from typing import List, Optional

from pcdlint.models import Diagnostic
from pcdlint.taint import TaintTracker


class RuleEngine:
    """Applies all 4 lint rules against analyzed code."""

    def __init__(self, tracker: TaintTracker) -> None:
        self.tracker = tracker
        self._diagnostics: List[Diagnostic] = []
        self._file_path: str = ""
        self._llm_used_vars: set = set()
        self._prompt_vars: set = set()
        self._json_dumps_to_var: dict = {}

    def prepare(self, tree: ast.AST) -> None:
        """Pre-scan AST to identify prompt variables and LLM arguments."""
        for node in ast.walk(tree):
            if isinstance(node, (ast.Assign, ast.AnnAssign)):
                target_names = []
                if isinstance(node, ast.Assign):
                    target_names = [t.id for t in node.targets if isinstance(t, ast.Name)]
                elif isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
                    target_names = [node.target.id]

                value = node.value
                if value:
                    for name in target_names:
                        if any(kw in name.lower() for kw in ("prompt", "system", "prefix", "instruction", "rules", "context")):
                            self._prompt_vars.add(name)
                        for sub in ast.walk(value):
                            if isinstance(sub, ast.Call) and self._is_json_dumps(sub):
                                self._json_dumps_to_var[sub] = name

            elif isinstance(node, ast.Call) and self._is_llm_api_call(node):
                for child in ast.walk(node):
                    if isinstance(child, ast.Name):
                        self._llm_used_vars.add(child.id)

    def _flows_into_prompt_or_llm(self, node: ast.Call) -> bool:
        """Check if json.dumps call flows into an LLM call or prompt variable."""
        assigned_var = self._json_dumps_to_var.get(node)
        if assigned_var:
            if assigned_var in self._llm_used_vars or assigned_var in self._prompt_vars:
                return True
            if any(kw in assigned_var.lower() for kw in ("prompt", "system", "prefix", "instruction", "rules", "context")):
                return True

        for var_name in self.tracker._json_unsorted_vars:
            if var_name in self._llm_used_vars or var_name in self._prompt_vars:
                return True

        return False

    def run(self, file_path: str) -> List[Diagnostic]:
        self._file_path = file_path
        self._diagnostics = []
        return self._diagnostics

    def _add(self, lineno: int, col_offset: int, rule_id: str, rule_name: str,
             message: str, fix_suggestion: str, severity: str) -> None:
        self._diagnostics.append(Diagnostic(
            file_path=self._file_path,
            lineno=lineno,
            col_offset=col_offset,
            rule_id=rule_id,
            rule_name=rule_name,
            message=message,
            fix_suggestion=fix_suggestion,
            severity=severity,
        ))

    def check_node(self, node: ast.AST) -> None:
        self._check_pcl001(node)
        self._check_pcl002(node)
        self._check_pcl003(node)
        self._check_pcl004(node)

    def _is_llm_api_call(self, node: ast.Call) -> bool:
        func = node.func
        if isinstance(func, ast.Attribute):
            parts = []
            current = func
            while isinstance(current, ast.Attribute):
                parts.append(current.attr)
                current = current.value
            if isinstance(current, ast.Name):
                parts.append(current.id)
            full_name = ".".join(reversed(parts))
            if "completions" in full_name and "create" in full_name:
                return True
            if "messages" in full_name and "create" in full_name:
                return True
            if "responses" in full_name and "create" in full_name:
                return True
        keywords = {kw.arg for kw in node.keywords if kw.arg}
        if "messages" in keywords and ("model" in keywords or "system" in keywords):
            return True
        return False

    def _get_system_arg(self, node: ast.Call) -> Optional[ast.keyword]:
        for kw in node.keywords:
            if kw.arg == "system":
                return kw
        return None

    def _get_messages_arg(self, node: ast.Call) -> Optional[ast.keyword]:
        for kw in node.keywords:
            if kw.arg == "messages":
                return kw
        return None

    def _get_tools_arg(self, node: ast.Call) -> Optional[ast.keyword]:
        for kw in node.keywords:
            if kw.arg == "tools":
                return kw
        return None

    def _resolve_dict_node(self, node: ast.AST) -> Optional[ast.Dict]:
        if isinstance(node, ast.Dict):
            return node
        if isinstance(node, ast.Name) and node.id in self.tracker._dict_vars:
            return self.tracker._dict_vars[node.id]
        return None

    def _is_system_message(self, msg: ast.Dict) -> bool:
        for key, val in zip(msg.keys, msg.values):
            if isinstance(key, ast.Constant) and key.value == "role":
                if isinstance(val, ast.Constant) and val.value in ("system", "developer"):
                    return True
        return False

    def _has_cache_control(self, node: ast.AST) -> bool:
        for sub in ast.walk(node):
            if isinstance(sub, ast.Constant) and sub.value == "cache_control":
                return True
        return False

    # --- PCL001: prefix-taint-injection ---

    def _check_pcl001(self, node: ast.AST) -> None:
        if not isinstance(node, ast.Call):
            return
        if not self._is_llm_api_call(node):
            return

        # Check `system=...` keyword argument
        system_kw = self._get_system_arg(node)
        if system_kw:
            system_val = system_kw.value
            # System can be a list of content blocks (Anthropic)
            if isinstance(system_val, ast.List):
                for block in system_val.elts:
                    resolved_block = self._resolve_dict_node(block)
                    if resolved_block:
                        for val in resolved_block.values:
                            origin = self.tracker.get_prefix_tainted(val)
                            if origin:
                                self._add(
                                    lineno=getattr(val, "lineno", getattr(block, "lineno", node.lineno)),
                                    col_offset=getattr(val, "col_offset", 0),
                                    rule_id="PCL001",
                                    rule_name="prefix-taint-injection",
                                    message=f"Prefix taint detected: '{origin.source_call}' in system prompt",
                                    fix_suggestion=f"Move dynamic value '{origin.source_call}' to the end of the static prompt or into the final user message to preserve prefix cache hits.",
                                    severity="ERROR",
                                )
                                break
            elif isinstance(system_val, ast.Name) and system_val.id in self.tracker._list_vars:
                for block in self.tracker._list_vars[system_val.id].elts:
                    resolved_block = self._resolve_dict_node(block)
                    if resolved_block:
                        for val in resolved_block.values:
                            origin = self.tracker.get_prefix_tainted(val)
                            if origin:
                                self._add(
                                    lineno=getattr(val, "lineno", node.lineno),
                                    col_offset=getattr(val, "col_offset", 0),
                                    rule_id="PCL001",
                                    rule_name="prefix-taint-injection",
                                    message=f"Prefix taint detected: '{origin.source_call}' in system prompt",
                                    fix_suggestion=f"Move dynamic value '{origin.source_call}' to the end of the static prompt or into the final user message to preserve prefix cache hits.",
                                    severity="ERROR",
                                )
                                break
            else:
                origin = self.tracker.get_prefix_tainted(system_val)
                if origin:
                    self._add(
                        lineno=getattr(system_val, "lineno", node.lineno),
                        col_offset=getattr(system_val, "col_offset", 0),
                        rule_id="PCL001",
                        rule_name="prefix-taint-injection",
                        message=f"Prefix taint detected: '{origin.source_call}' in system prompt",
                        fix_suggestion=f"Move dynamic value '{origin.source_call}' to the end of the static prompt or into the final user message to preserve prefix cache hits.",
                        severity="ERROR",
                    )

        # Check `messages=[...]` keyword argument
        messages_kw = self._get_messages_arg(node)
        if messages_kw:
            msg_elts = []
            if isinstance(messages_kw.value, ast.List):
                msg_elts = messages_kw.value.elts
            elif isinstance(messages_kw.value, ast.Name) and messages_kw.value.id in self.tracker._list_vars:
                msg_elts = self.tracker._list_vars[messages_kw.value.id].elts

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
                is_sys = self._is_system_message(resolved_dict)
                has_cache = self._has_cache_control(resolved_dict)
                if is_sys or idx == 0 or has_cache or (last_cache_idx != -1 and idx <= last_cache_idx):
                    for val in resolved_dict.values:
                        if isinstance(val, ast.List):
                            for sub in val.elts:
                                sub_dict = self._resolve_dict_node(sub)
                                if sub_dict:
                                    for sub_val in sub_dict.values:
                                        origin = self.tracker.get_prefix_tainted(sub_val)
                                        if origin:
                                            self._add(
                                                lineno=getattr(sub_val, "lineno", resolved_dict.lineno),
                                                col_offset=getattr(sub_val, "col_offset", 0),
                                                rule_id="PCL001",
                                                rule_name="prefix-taint-injection",
                                                message=f"Prefix taint detected: '{origin.source_call}' in message prefix",
                                                fix_suggestion=f"Move dynamic value '{origin.source_call}' to the end of the static prompt or into the final user message to preserve prefix cache hits.",
                                                severity="ERROR",
                                            )
                                            break
                        else:
                            origin = self.tracker.get_prefix_tainted(val)
                            if origin:
                                self._add(
                                    lineno=getattr(val, "lineno", resolved_dict.lineno),
                                    col_offset=getattr(val, "col_offset", 0),
                                    rule_id="PCL001",
                                    rule_name="prefix-taint-injection",
                                    message=f"Prefix taint detected: '{origin.source_call}' in message prefix",
                                    fix_suggestion=f"Move dynamic value '{origin.source_call}' to the end of the static prompt or into the final user message to preserve prefix cache hits.",
                                    severity="ERROR",
                                )
                                break

    # --- PCL002: unsorted-json-in-prefix ---

    def _check_pcl002(self, node: ast.AST) -> None:
        if not isinstance(node, ast.Call):
            return
        if not self._is_json_dumps(node):
            return
        has_sort_keys_true = False
        for kw in node.keywords:
            if kw.arg == "sort_keys":
                if isinstance(kw.value, ast.Constant) and kw.value.value is True:
                    has_sort_keys_true = True
        if not has_sort_keys_true:
            if self._flows_into_prompt_or_llm(node):
                self._add(
                    lineno=node.lineno,
                    col_offset=node.col_offset,
                    rule_id="PCL002",
                    rule_name="unsorted-json-in-prefix",
                    message="json.dumps() called without sort_keys=True",
                    fix_suggestion="Pass 'sort_keys=True' to 'json.dumps(...)' to guarantee deterministic key serialization across requests.",
                    severity="WARNING",
                )

    def _is_json_dumps(self, node: ast.Call) -> bool:
        if isinstance(node.func, ast.Attribute):
            if isinstance(node.func.value, ast.Name) and node.func.value.id == "json":
                if node.func.attr == "dumps":
                    return True
        return False

    # --- PCL003: set-iteration-in-prompt ---

    def _is_unsorted_set_expr(self, expr: ast.AST) -> bool:
        """Check if an expression is an unsorted set (not wrapped in sorted)."""
        if isinstance(expr, ast.Call):
            if isinstance(expr.func, ast.Name) and expr.func.id == "sorted":
                return False
            if isinstance(expr.func, ast.Name) and expr.func.id == "set":
                return True
        if isinstance(expr, ast.Name):
            return self.tracker.is_set_variable(expr.id)
        if isinstance(expr, (ast.Set, ast.SetComp)):
            return True
        return False

    def _check_pcl003(self, node: ast.AST) -> None:
        # Check join calls: "...".join(tag_set)
        if isinstance(node, ast.Call):
            if isinstance(node.func, ast.Attribute) and node.func.attr == "join":
                if node.args and self._is_unsorted_set_expr(node.args[0]):
                    self._add(
                        lineno=node.lineno,
                        col_offset=node.col_offset,
                        rule_id="PCL003",
                        rule_name="set-iteration-in-prompt",
                        message="Set iterated in join() without sorted() - iteration order is non-deterministic",
                        fix_suggestion="Wrap the set in 'sorted(...)' before string conversion; Python's PYTHONHASHSEED randomizes set iteration order across processes.",
                        severity="ERROR",
                    )
                    return
            # Check str(tag_set)
            if isinstance(node.func, ast.Name) and node.func.id == "str":
                if node.args and self._is_unsorted_set_expr(node.args[0]):
                    self._add(
                        lineno=node.lineno,
                        col_offset=node.col_offset,
                        rule_id="PCL003",
                        rule_name="set-iteration-in-prompt",
                        message="Set converted to string without sorted() - iteration order is non-deterministic",
                        fix_suggestion="Wrap the set in 'sorted(...)' before string conversion; Python's PYTHONHASHSEED randomizes set iteration order across processes.",
                        severity="ERROR",
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
                        fix_suggestion="Wrap the set in 'sorted(...)' before string conversion; Python's PYTHONHASHSEED randomizes set iteration order across processes.",
                        severity="ERROR",
                    )
                    return

    # --- PCL004: dynamic-tools-mutation ---

    def _check_pcl004(self, node: ast.AST) -> None:
        if not isinstance(node, ast.Call):
            return
        if not self._is_llm_api_call(node):
            return
        tools_kw = self._get_tools_arg(node)
        if not tools_kw:
            return
        tools_var = tools_kw.value
        if isinstance(tools_var, ast.Name):
            var_name = tools_var.id
            if (self.tracker.is_tainted_variable(var_name)
                    or self.tracker.is_tools_mutated(var_name)
                    or self.tracker.is_set_variable(var_name)):
                self._add(
                    lineno=tools_var.lineno,
                    col_offset=tools_var.col_offset,
                    rule_id="PCL004",
                    rule_name="dynamic-tools-mutation",
                    message=f"Tools list '{var_name}' may have been dynamically mutated",
                    fix_suggestion="Keep the 'tools' list order strictly static and deterministic; changing tool order invalidates the entire prompt cache hierarchy.",
                    severity="WARNING",
                )
        elif isinstance(tools_var, (ast.Set, ast.SetComp)):
            self._add(
                lineno=getattr(tools_var, "lineno", node.lineno),
                col_offset=getattr(tools_var, "col_offset", 0),
                rule_id="PCL004",
                rule_name="dynamic-tools-mutation",
                message="Tools list passed as set with non-deterministic order",
                fix_suggestion="Keep the 'tools' list order strictly static and deterministic; changing tool order invalidates the entire prompt cache hierarchy.",
                severity="WARNING",
            )
        elif isinstance(tools_var, ast.Call) and isinstance(tools_var.func, ast.Name) and tools_var.func.id == "list" and tools_var.args:
            arg = tools_var.args[0]
            if (isinstance(arg, ast.Name) and self.tracker.is_set_variable(arg.id)) or isinstance(arg, (ast.Set, ast.SetComp)):
                self._add(
                    lineno=tools_var.lineno,
                    col_offset=tools_var.col_offset,
                    rule_id="PCL004",
                    rule_name="dynamic-tools-mutation",
                    message="Tools list constructed from set without deterministic ordering",
                    fix_suggestion="Keep the 'tools' list order strictly static and deterministic; changing tool order invalidates the entire prompt cache hierarchy.",
                    severity="WARNING",
                )
