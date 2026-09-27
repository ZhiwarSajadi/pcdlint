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

    def _is_system_message(self, msg: ast.Dict) -> bool:
        for key, val in zip(msg.keys, msg.values):
            if isinstance(key, ast.Constant) and key.value == "role":
                if isinstance(val, ast.Constant) and val.value in ("system", "developer"):
                    return True
        return False

    def _has_cache_control(self, msg: ast.Dict) -> bool:
        for key in msg.keys:
            if isinstance(key, ast.Constant) and key.value == "cache_control":
                return True
        return False

    # --- PCL001: prefix-taint-injection ---

    def _check_pcl001(self, node: ast.AST) -> None:
        if not isinstance(node, ast.Call):
            return
        if not self._is_llm_api_call(node):
            return

        system_kw = self._get_system_arg(node)
        if system_kw:
            origin = self.tracker.get_prefix_tainted(system_kw.value)
            if origin:
                self._add(
                    lineno=getattr(system_kw.value, 'lineno', node.lineno),
                    col_offset=getattr(system_kw.value, 'col_offset', 0),
                    rule_id="PCL001",
                    rule_name="prefix-taint-injection",
                    message=f"Prefix taint detected: '{origin.source_call}' in system prompt",
                    fix_suggestion=f"Move dynamic value '{origin.source_call}' to the end of the static prompt or into the final user message to preserve prefix cache hits.",
                    severity="ERROR",
                )

        messages_kw = self._get_messages_arg(node)
        if messages_kw and isinstance(messages_kw.value, ast.List):
            for idx, msg_node in enumerate(messages_kw.value.elts):
                if not isinstance(msg_node, ast.Dict):
                    continue
                if self._is_system_message(msg_node):
                    for val in msg_node.values:
                        origin = self.tracker.get_prefix_tainted(val)
                        if origin:
                            self._add(
                                lineno=getattr(val, 'lineno', msg_node.lineno),
                                col_offset=getattr(val, 'col_offset', 0),
                                rule_id="PCL001",
                                rule_name="prefix-taint-injection",
                                message=f"Prefix taint detected: '{origin.source_call}' in system message",
                                fix_suggestion=f"Move dynamic value '{origin.source_call}' to the end of the static prompt or into the final user message to preserve prefix cache hits.",
                                severity="ERROR",
                            )
                            break
                has_cache = self._has_cache_control(msg_node)
                if has_cache or idx == 0:
                    for val in msg_node.values:
                        origin = self.tracker.get_prefix_tainted(val)
                        if origin:
                            self._add(
                                lineno=getattr(val, 'lineno', msg_node.lineno),
                                col_offset=getattr(val, 'col_offset', 0),
                                rule_id="PCL001",
                                rule_name="prefix-taint-injection",
                                message=f"Prefix taint detected: '{origin.source_call}' in message block near cache_control",
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
        has_sort_keys_kwarg = False
        for kw in node.keywords:
            if kw.arg == "sort_keys":
                has_sort_keys_kwarg = True
                if isinstance(kw.value, ast.Constant) and kw.value.value is True:
                    has_sort_keys_true = True
        if not has_sort_keys_true:
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

    def _check_pcl003(self, node: ast.AST) -> None:
        if not isinstance(node, ast.Call):
            return
        if self.tracker.is_str_set_operation(node):
            if not self.tracker.is_sorted_wrap(node):
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
        if isinstance(node.func, ast.Attribute) and node.func.attr == "join":
            if node.args and isinstance(node.args[0], ast.Name):
                var_name = node.args[0].id
                if self.tracker.is_set_variable(var_name):
                    if not self.tracker.is_sorted_wrap(node.args[0]):
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
        if isinstance(node, ast.JoinedStr):
            for part in node.values:
                if isinstance(part, ast.FormattedValue) and isinstance(part.value, ast.Name):
                    if self.tracker.is_set_variable(part.value.id):
                        if not self.tracker.is_sorted_wrap(part.value):
                            self._add(
                                lineno=node.lineno,
                                col_offset=node.col_offset,
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
            if self.tracker.is_tainted_variable(var_name) or self.tracker.is_shuffled_variable(var_name):
                self._add(
                    lineno=tools_var.lineno,
                    col_offset=tools_var.col_offset,
                    rule_id="PCL004",
                    rule_name="dynamic-tools-mutation",
                    message=f"Tools list '{var_name}' may have been dynamically mutated",
                    fix_suggestion="Keep the 'tools' list order strictly static and deterministic; changing tool order invalidates the entire prompt cache hierarchy.",
                    severity="WARNING",
                )