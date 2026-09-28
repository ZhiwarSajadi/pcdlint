"""Regression tests for correctness/robustness fixes (see audit findings)."""

import sys
import textwrap

import pytest

from pcdlint.analyzer import analyze_code


def _codes(source: str, path: str = "case.py") -> list:
    return [d.rule_id for d in analyze_code(textwrap.dedent(source), path)]


# --- Issue 1: repeated static string must count as a static prefix solid ---

def test_mult_static_prefix_not_flagged() -> None:
    """`"X " * N + f"{taint}"` puts taint at the end of a long static prefix."""
    source = '''
        from datetime import datetime
        SYSTEM_PROMPT = "STATIC RULES AND INSTRUCTIONS " * 10 + f" {datetime.now()}"
        client.messages.create(model="m", system=SYSTEM_PROMPT)
    '''
    assert _codes(source) == []


def test_mult_static_prefix_taint_first_still_flagged() -> None:
    """Taint before the repeated static block must still be reported."""
    source = '''
        from datetime import datetime
        SYSTEM_PROMPT = f"{datetime.now()} " + "STATIC RULES AND INSTRUCTIONS " * 10
        client.messages.create(model="m", system=SYSTEM_PROMPT)
    '''
    assert _codes(source) == ["PCL001"]


# --- Issue 2: an uppercase tainted name must not act as its own static solid ---

def test_uppercase_taint_first_flagged() -> None:
    source = '''
        from datetime import datetime
        STAMP = f"Time: {datetime.now()}"
        SYSTEM_PROMPT = STAMP + " and then a long static tail " * 10
        client.messages.create(model="m", system=SYSTEM_PROMPT)
    '''
    assert _codes(source) == ["PCL001"]


# --- Issue 3a: reassignment must kill earlier taint state ---

def test_reassignment_clears_prefix_taint() -> None:
    source = '''
        from datetime import datetime
        ts = datetime.now()
        ts = "2020-01-01 static"
        SYSTEM_PROMPT = f"{ts} fixed tail"
        client.messages.create(model="m", system=SYSTEM_PROMPT)
    '''
    assert _codes(source) == []


def test_reassignment_clears_set_state() -> None:
    source = '''
        tags = {"b", "a"}
        tags = ["b", "a"]
        SYSTEM_PROMPT = ", ".join(tags)
        client.messages.create(model="m", system=SYSTEM_PROMPT)
    '''
    assert _codes(source) == []


def test_reassignment_clears_tools_mutation() -> None:
    source = '''
        tools = [{"name": "a"}]
        if x:
            tools.append({"name": "b"})
        tools = [{"name": "a"}, {"name": "b"}]
        client.messages.create(model="m", tools=tools)
    '''
    assert _codes(source) == []


# --- Issue 3b: bindings must not leak across function scopes ---

def test_function_scopes_are_isolated() -> None:
    source = '''
        from datetime import datetime

        def handler():
            system = f"Time: {datetime.now()}"
            return client.messages.create(model="m", system=system)

        def safe():
            system = "totally static prompt " * 40
            return client.messages.create(model="m", system=system)
    '''
    codes = _codes(source)
    assert codes.count("PCL001") == 1


def test_module_scope_sees_module_bindings() -> None:
    source = '''
        from datetime import datetime
        SYSTEM_PROMPT = f"Time: {datetime.now()}"
        client.messages.create(model="m", system=SYSTEM_PROMPT)
    '''
    assert _codes(source) == ["PCL001"]


def test_method_scopes_are_isolated() -> None:
    source = '''
        from datetime import datetime

        class Handler:
            def bad(self):
                system = f"Time: {datetime.now()}"
                return client.messages.create(model="m", system=system)

            def good(self):
                system = "static instructions " * 40
                return client.messages.create(model="m", system=system)
    '''
    assert _codes(source).count("PCL001") == 1


# --- Issue 10: taint inside join()/list arguments must propagate ---

def test_taint_through_join_of_fstring_list() -> None:
    """Taint reached through ``join([...])`` must still be detected.

    The static head is kept short so rule 2 (static solid first) cannot mask it.
    """
    source = '''
        from datetime import datetime
        SYSTEM_PROMPT = "head: " + ", ".join([f"{datetime.now()}"])
        client.messages.create(model="m", system=SYSTEM_PROMPT)
    '''
    assert _codes(source) == ["PCL001"]


# --- Issue 6: unsorted json.dumps must flow through an intermediate variable ---

def test_pcl002_flows_through_intermediate_var() -> None:
    source = '''
        import json
        blob = json.dumps({"z": 1, "a": 2})
        SYSTEM_PROMPT = "head " * 50 + blob
        client.messages.create(model="m", system=SYSTEM_PROMPT)
    '''
    assert "PCL002" in _codes(source)


def test_pcl002_ignores_dumps_that_never_reach_a_prompt() -> None:
    source = '''
        import json
        cache = json.dumps({"a": 1})
        SYSTEM_PROMPT = "static instructions " * 20
        client.messages.create(model="m", system=SYSTEM_PROMPT)
    '''
    assert _codes(source) == []


# --- Issue 7: taint returned by a local function ---

def test_taint_through_function_return() -> None:
    source = '''
        from datetime import datetime

        def build():
            return f"Time: {datetime.now()}"

        SYSTEM_PROMPT = build()
        client.messages.create(model="m", system=SYSTEM_PROMPT)
    '''
    assert _codes(source) == ["PCL001"]


def test_clean_function_return_not_flagged() -> None:
    source = '''
        def build():
            return "static instructions " * 40

        SYSTEM_PROMPT = build()
        client.messages.create(model="m", system=SYSTEM_PROMPT)
    '''
    assert _codes(source) == []


# --- Issue 8: tools assembled from a conditionally assigned helper ---

def test_pcl004_tools_from_branch_assigned_helper() -> None:
    source = '''
        if FLAG:
            base = [{"name": "a"}]
        else:
            base = [{"name": "b"}]
        tools = base + [{"name": "c"}]
        client.messages.create(model="m", tools=tools)
    '''
    assert "PCL004" in _codes(source)


def test_pcl004_ignores_tools_built_from_static_parts() -> None:
    source = '''
        base = [{"name": "a"}]
        tools = base + [{"name": "c"}]
        client.messages.create(model="m", tools=tools)
    '''
    assert _codes(source) == []


# --- Issue 9: positional arguments to an LLM call ---

def test_pcl001_positional_messages_arg() -> None:
    source = '''
        from datetime import datetime
        client.messages.create(
            "m",
            [{"role": "system", "content": f"Time: {datetime.now()}"}],
        )
    '''
    assert _codes(source) == ["PCL001"]


# --- Issues 4 & 5: paths that cannot be analyzed must not look clean ---

def _run_cli(*argv: str) -> int:
    import sys

    from pcdlint.cli import main

    old_argv = sys.argv
    try:
        sys.argv = ["pcdlint", *argv]
        return main()
    finally:
        sys.argv = old_argv


def test_analyze_path_ex_reports_invalid_utf8(tmp_path) -> None:
    from pcdlint.analyzer import analyze_path_ex

    bad = tmp_path / "bad.py"
    bad.write_bytes(b'x = "\xff\xfe"\n')
    diagnostics, errors = analyze_path_ex(bad)
    assert diagnostics == []
    assert len(errors) == 1
    assert "UTF-8" in errors[0]


def test_analyze_path_ex_reports_missing_path(tmp_path) -> None:
    from pcdlint.analyzer import analyze_path_ex

    diagnostics, errors = analyze_path_ex(tmp_path / "does_not_exist")
    assert diagnostics == []
    assert errors and "does not exist" in errors[0]


def test_analyze_path_ex_reports_non_python_file(tmp_path) -> None:
    from pcdlint.analyzer import analyze_path_ex

    other = tmp_path / "notes.txt"
    other.write_text("not python", encoding="utf-8")
    diagnostics, errors = analyze_path_ex(other)
    assert diagnostics == []
    assert errors and "not a Python file" in errors[0]


def test_analyze_path_ex_reports_syntax_error(tmp_path) -> None:
    from pcdlint.analyzer import analyze_path_ex

    broken = tmp_path / "broken.py"
    broken.write_text("def broken(:\n", encoding="utf-8")
    diagnostics, errors = analyze_path_ex(broken)
    assert diagnostics == []
    assert errors and "cannot parse" in errors[0]


def test_analyze_path_ex_reports_unreadable_file_in_directory(tmp_path) -> None:
    from pcdlint.analyzer import analyze_path_ex

    (tmp_path / "good.py").write_text("x = 1\n", encoding="utf-8")
    (tmp_path / "bad.py").write_bytes(b'x = "\xff\xfe"\n')
    _diagnostics, errors = analyze_path_ex(tmp_path)
    assert errors and "bad.py" in errors[0]


def test_cli_missing_path_exits_2(capsys) -> None:
    code = _run_cli("check", "definitely_missing_dir_xyz")
    captured = capsys.readouterr()
    assert code == 2
    assert "does not exist" in captured.err


def test_cli_non_python_file_exits_2(tmp_path, capsys) -> None:
    other = tmp_path / "notes.txt"
    other.write_text("not python", encoding="utf-8")
    code = _run_cli("check", str(other))
    captured = capsys.readouterr()
    assert code == 2
    assert "not a Python file" in captured.err


def test_cli_syntax_error_exits_2(tmp_path, capsys) -> None:
    broken = tmp_path / "broken.py"
    broken.write_text("def broken(:\n", encoding="utf-8")
    code = _run_cli("check", str(broken))
    captured = capsys.readouterr()
    assert code == 2
    assert "cannot parse" in captured.err
    # stdout must stay parseable for --format json consumers
    json_code = _run_cli("check", str(broken), "--format", "json")
    captured = capsys.readouterr()
    assert json_code == 2
    assert captured.out.strip() == "[]"


def test_cli_valid_path_still_exits_0(tmp_path, capsys) -> None:
    good = tmp_path / "good.py"
    good.write_text("x = 1\n", encoding="utf-8")
    assert _run_cli("check", str(good)) == 0
    assert "does not exist" not in capsys.readouterr().err


def test_cli_check_without_paths_defaults_to_cwd(tmp_path, capsys, monkeypatch) -> None:
    (tmp_path / "ok.py").write_text("x = 1\n", encoding="utf-8")
    monkeypatch.chdir(tmp_path)
    assert _run_cli("check") == 0
    assert "No issues found!" in capsys.readouterr().out


# --- Coverage: augmented assignments (+=) ---

def test_augmented_string_concat_prefix_taint() -> None:
    source = '''
        from datetime import datetime
        SYSTEM_PROMPT = "head: "
        SYSTEM_PROMPT += f"{datetime.now()}"
        client.messages.create(model="m", system=SYSTEM_PROMPT)
    '''
    assert _codes(source) == ["PCL001"]


def test_augmented_messages_list_taint() -> None:
    source = '''
        from datetime import datetime
        messages = []
        messages += [{"role": "system", "content": f"Time: {datetime.now()}"}]
        client.messages.create(model="m", messages=messages)
    '''
    assert _codes(source) == ["PCL001"]


def test_augmented_tools_list_flagged() -> None:
    source = '''
        tools = [{"name": "a"}]
        tools += [{"name": "b"}]
        client.messages.create(model="m", tools=tools)
    '''
    assert "PCL004" in _codes(source)


# --- Coverage: tools= passed inline rather than as a name ---

def test_pcl004_inline_set_literal_tools() -> None:
    source = '''
        client.messages.create(model="m", tools={"a", "b"})
    '''
    assert "PCL004" in _codes(source)


def test_pcl004_inline_list_from_set_tools() -> None:
    source = '''
        tool_set = {"a", "b"}
        client.messages.create(model="m", tools=list(tool_set))
    '''
    assert "PCL004" in _codes(source)


# --- Coverage: error reporting while walking a directory ---

def test_directory_reports_parse_error_and_skips_non_python(tmp_path) -> None:
    from pcdlint.analyzer import analyze_path_ex

    (tmp_path / "good.py").write_text("x = 1\n", encoding="utf-8")
    (tmp_path / "broken.py").write_text("def broken(:\n", encoding="utf-8")
    (tmp_path / "notes.txt").write_text("ignored", encoding="utf-8")

    diagnostics, errors = analyze_path_ex(tmp_path)
    assert diagnostics == []
    assert len(errors) == 1
    assert "broken.py" in errors[0]


# --- Coverage: taint passed to system= as an expression, not a variable ---

def test_pcl001_inline_function_call_as_system() -> None:
    source = '''
        from datetime import datetime

        def build():
            return f"Time: {datetime.now()}"

        client.messages.create(model="m", system=build())
    '''
    assert _codes(source) == ["PCL001"]


def test_pcl001_inline_str_cast_as_system() -> None:
    source = '''
        from datetime import datetime
        ts = datetime.now()
        client.messages.create(model="m", system=str(ts))
    '''
    assert _codes(source) == ["PCL001"]


def test_pcl001_system_from_list_variable_of_blocks() -> None:
    source = '''
        from datetime import datetime
        SYSTEM_BLOCKS = [{"type": "text", "text": f"Time: {datetime.now()}"}]
        client.messages.create(model="m", system=SYSTEM_BLOCKS,
                               messages=[{"role": "user", "content": "hi"}])
    '''
    assert _codes(source) == ["PCL001"]


def test_pcl001_responses_api_is_recognized() -> None:
    source = '''
        from datetime import datetime
        client.responses.create(model="m", input=f"Time: {datetime.now()}")
    '''
    assert _codes(source) == ["PCL001"]


def test_pcl001_responses_instructions_are_a_system_prompt() -> None:
    """instructions= is the Responses API's system prompt, so it is a prefix."""
    source = '''
        from datetime import datetime
        client.responses.create(
            model="m",
            instructions=f"{datetime.now()}" + "STATIC RULES " * 30,
            input="hi",
        )
    '''
    assert _codes(source) == ["PCL001"]


def test_pcl001_taint_before_cache_control_breakpoint() -> None:
    """A cache breakpoint marks every earlier message as part of the cached prefix."""
    source = '''
        from datetime import datetime
        messages = [
            {"role": "system", "content": "static instructions " * 20},
            {"role": "user", "content": f"Time: {datetime.now()}"},
            {"role": "user", "content": "tail",
             "cache_control": {"type": "ephemeral"}},
        ]
        client.messages.create(model="m", messages=messages)
    '''
    assert "PCL001" in _codes(source)


def test_pcl001_taint_after_last_message_without_breakpoint() -> None:
    """Same taint, but no cache breakpoint: the tail message is not prefix."""
    source = '''
        from datetime import datetime
        messages = [
            {"role": "system", "content": "static instructions " * 20},
            {"role": "user", "content": f"Time: {datetime.now()}"},
        ]
        client.messages.create(model="m", messages=messages)
    '''
    assert _codes(source) == []


# --- v0.2: branch-sensitive merging (if/else, IfExp, try/except) ---

def test_branch_identical_static_tools_not_flagged() -> None:
    """Both arms bind the same static list, so tool order cannot vary."""
    source = '''
        if flag:
            tools = [tool_a, tool_b]
        else:
            tools = [tool_a, tool_b]
        client.messages.create(model="m", messages=[], tools=tools)
    '''
    assert _codes(source) == []


def test_branch_disagreeing_tools_still_flagged() -> None:
    """Arms disagree -> the name really is conditionally constructed."""
    source = '''
        tools = []
        if flag:
            tools.append(tool_c)
        client.messages.create(model="m", messages=[], tools=tools)
    '''
    assert _codes(source) == ["PCL004"]


def test_append_over_static_list_not_flagged() -> None:
    """Iterating a list literal yields a deterministic order."""
    source = '''
        SPEC = [tool_a, tool_b]
        tools = []
        for t in SPEC:
            tools.append(t)
        client.messages.create(model="m", messages=[], tools=tools)
    '''
    assert _codes(source) == []


def test_append_over_set_still_flagged() -> None:
    """A set iterator is exactly the non-determinism PCL004 exists to catch."""
    source = '''
        SPEC = {tool_a, tool_b}
        tools = []
        for t in SPEC:
            tools.append(t)
        client.messages.create(model="m", messages=[], tools=tools)
    '''
    assert _codes(source) == ["PCL004"]


def test_pcl001_taint_only_in_ifexp_true_branch() -> None:
    """A conditional expression carries taint when either arm is tainted."""
    source = '''
        from datetime import datetime
        system = f"{datetime.now()} " + "STATIC RULES " * 30 if flag else "STATIC RULES " * 30
        client.messages.create(model="m", system=system)
    '''
    assert _codes(source) == ["PCL001"]


def test_pcl001_taint_only_in_try_body() -> None:
    """The handler must not erase taint recorded on the try path."""
    source = '''
        from datetime import datetime
        try:
            system = f"{datetime.now()} " + "STATIC RULES " * 30
        except Exception:
            system = "STATIC RULES " * 30
        client.messages.create(model="m", system=system)
    '''
    assert _codes(source) == ["PCL001"]


def test_pcl001_taint_only_in_else_branch_kept() -> None:
    """May-analysis: taint on the else path alone must still be reported."""
    source = '''
        from datetime import datetime
        if flag:
            system = "STATIC RULES " * 30
        else:
            system = f"{datetime.now()} " + "STATIC RULES " * 30
        client.messages.create(model="m", system=system)
    '''
    assert _codes(source) == ["PCL001"]


def test_both_branches_static_prompt_not_flagged() -> None:
    """Two static arms agree, so the prompt is deterministic either way."""
    source = '''
        if flag:
            system = "STATIC RULES " * 30
        else:
            system = "STATIC RULES " * 30 + " more"
        client.messages.create(model="m", system=system)
    '''
    assert _codes(source) == []


# --- v0.2: interprocedural summaries resolved to a fixpoint ---

def test_pcl001_function_chain_declared_in_reverse_order() -> None:
    """Callers declared before their callees must still resolve, at any depth."""
    source = '''
        from datetime import datetime
        def outer():
            return middle()
        def middle():
            return inner()
        def inner():
            return datetime.now()
        system = f"{outer()} " + "STATIC RULES " * 30
        client.messages.create(model="m", system=system)
    '''
    assert _codes(source) == ["PCL001"]


def test_pcl004_function_returning_a_set() -> None:
    """A callee's set-ness has to reach the caller, not just its taint."""
    source = '''
        def get_tools():
            return {tool_a, tool_b, tool_c}
        tools = list(get_tools())
        client.messages.create(model="m", messages=[], tools=tools)
    '''
    assert _codes(source) == ["PCL004"]


def test_pcl002_function_returning_unsorted_json() -> None:
    """A callee's unsorted json.dumps has to flow into the prompt variable."""
    source = '''
        import json
        def payload():
            return json.dumps(data)
        prompt = "Prompt header " * 30 + payload()
        client.messages.create(
            model="m", messages=[{"role": "user", "content": prompt}])
    '''
    assert _codes(source) == ["PCL002"]


def test_pcl004_direct_function_return_of_set() -> None:
    """Assigning the callee's result straight to ``tools`` is the same risk."""
    source = '''
        def get_tools():
            return {tool_a, tool_b}
        tools = get_tools()
        client.messages.create(model="m", messages=[], tools=tools)
    '''
    assert _codes(source) == ["PCL004"]

# --- PCL003 only fires when the set iteration reaches a prompt -----------

def test_pcl003_not_reported_when_set_never_reaches_a_prompt() -> None:
    """A log line joining a set is not a prompt; PCL003 is named for prompts.

    It is an ERROR with an autofix, so firing file-wide turns every
    ``", ".join(some_set)`` in the tree into a build failure.
    """
    source = '''
        tags = {"a", "b"}
        line = ", ".join(tags)
        print(line)
    '''
    assert _codes(source) == []


def test_pcl003_still_reported_when_set_reaches_the_messages() -> None:
    source = '''
        tags = {"a", "b"}
        prompt = ", ".join(tags)
        client.messages.create(model="m", messages=[
            {"role": "user", "content": prompt}])
    '''
    assert _codes(source) == ["PCL003"]


def test_pcl003_still_reported_when_joined_inline_in_the_call() -> None:
    source = '''
        tags = {"a", "b"}
        client.messages.create(model="m", messages=[
            {"role": "user", "content": ", ".join(tags)}])
    '''
    assert _codes(source) == ["PCL003"]


def test_pcl003_still_reported_for_an_interpolation_in_the_messages() -> None:
    source = '''
        tags = {"a", "b"}
        prompt = f"Tags: {tags}"
        client.messages.create(model="m", system=prompt)
    '''
    assert _codes(source) == ["PCL003"]


# --- json.dumps reachability: inline and via an import alias -------------

def test_pcl002_reported_when_dumps_is_passed_inline_to_the_call() -> None:
    """json_flows is only populated by assignment, so an inline payload
    produced nothing to look up and the finding vanished."""
    source = '''
        import json
        client.messages.create(model="m", messages=[
            {"role": "user", "content": json.dumps({"b": 1, "a": 2})}])
    '''
    assert _codes(source) == ["PCL002"]


def test_pcl002_sees_a_dumps_imported_by_name() -> None:
    """The tracker accepts bare ``dumps`` but the rule demanded ``json.dumps``,
    so the provenance was recorded and then never reported."""
    source = '''
        from json import dumps
        payload = dumps({"b": 1, "a": 2})
        client.messages.create(model="m", messages=[
            {"role": "user", "content": payload}])
    '''
    assert _codes(source) == ["PCL002"]


def test_pcl002_still_silent_when_the_payload_never_reaches_a_prompt() -> None:
    source = '''
        import json
        audit = json.dumps({"b": 1, "a": 2})
        print(audit)
    '''
    assert _codes(source) == []


def test_pcl002_sees_dumps_through_a_module_alias() -> None:
    """``import json as J`` spells the same non-determinism as ``json.dumps``."""
    source = '''
        import json as J
        payload = J.dumps({"b": 1, "a": 2})
        client.messages.create(model="m", messages=[
            {"role": "user", "content": payload}])
    '''
    assert _codes(source) == ["PCL002"]


# --- what is allowed to count as a static prefix solid -------------------

def test_pcl001_not_silenced_by_an_uppercase_dynamic_value() -> None:
    """An UPPER_CASE name was accepted as static text on its name alone.

    So renaming a dynamic value to shouty case -- or merely having one the
    taint sources do not model, like ``input()`` -- hid a genuine prefix
    taint sitting right after it.
    """
    source = '''
        from datetime import datetime
        GREETING = input("hdr: ")
        now = datetime.now()
        system = f"{GREETING}Rules and instructions. " + f"{now}"
        client.messages.create(model="m", system=system)
    '''
    assert _codes(source) == ["PCL001"]


def test_pcl001_still_spared_by_a_known_static_uppercase_prompt() -> None:
    """Guard: an uppercase *string constant* is still a static solid."""
    source = '''
        from datetime import datetime
        STATIC_RULES = "You are a helpful assistant. Follow the rules. "
        now = datetime.now()
        system = f"{STATIC_RULES}Time: {now}"
        client.messages.create(model="m", system=system)
    '''
    assert _codes(source) == []


def test_pcl001_still_spared_by_a_listed_static_prefix_name() -> None:
    """Guard: the curated STATIC_PREFIX_NAMES list keeps working."""
    source = '''
        from datetime import datetime
        SYSTEM_PROMPT = build_prompt()
        now = datetime.now()
        system = f"{SYSTEM_PROMPT}Time: {now}"
        client.messages.create(model="m", system=system)
    '''
    assert _codes(source) == []


# --- what counts as an LLM sink ------------------------------------------

def test_pcl001_not_reported_for_a_local_helper_that_merely_takes_messages() -> None:
    """``messages=`` plus ``model=`` is not what makes a call an LLM call.

    Any local helper with those two keyword names was being treated as a
    sink, so its arguments were judged as prompt prefixes.
    """
    source = '''
        from datetime import datetime
        now = datetime.now()
        def render(messages, model):
            return messages[0]
        render(messages=[{"role": "user", "content": f"Time: {now}"}], model="m")
    '''
    assert _codes(source) == []


def test_pcl001_still_fires_on_the_real_sdk_shapes() -> None:
    """Guard: dropping the keyword fallback must not cost the known sinks."""
    source = '''
        from datetime import datetime
        now = datetime.now()
        client.chat.completions.create(
            model="m", messages=[{"role": "user", "content": f"T {now}"}])
        client.messages.create(
            model="m", messages=[{"role": "user", "content": f"T {now}"}])
        client.responses.create(
            model="m", messages=[{"role": "user", "content": f"T {now}"}])
    '''
    assert _codes(source) == ["PCL001", "PCL001", "PCL001"]


# --- cache and vendored directories are not source -----------------------

def test_cache_directories_are_not_linted(tmp_path) -> None:
    """A pytest cache full of .py scratch files is not source code.

    Walking them turned every cache the tooling leaves behind into more
    findings (and more exit-2 parse errors) than the project actually has.
    """
    from pcdlint.analyzer import analyze_path_ex

    buggy = (
        "from datetime import datetime\n"
        "client.messages.create(model='m', "
        "system=f'{datetime.now()}' + 'RULES ' * 30, messages=[])\n"
    )
    for name in (".pytest_cache", ".mypy_cache", "site-packages", "env"):
        nested = tmp_path / name
        nested.mkdir()
        (nested / "scratch.py").write_text(buggy, encoding="utf-8")
    (tmp_path / "real.py").write_text("x = 1\n", encoding="utf-8")

    diagnostics, errors = analyze_path_ex(tmp_path)

    assert errors == []
    assert diagnostics == [], (
        f"linted files under a skipped directory: "
        f"{sorted(d.file_path for d in diagnostics)}"
    )


# --- A UTF-8 BOM must not make a file unanalyzable -----------------------

def test_utf8_bom_file_is_analyzed_not_rejected(tmp_path) -> None:
    """Editors save UTF-8 with BOM; ast.parse rejects a leading U+FEFF.

    The file has to come back as lintable source, not as a parse error that
    makes the whole run exit 2.
    """
    from pcdlint.analyzer import analyze_path_ex

    source = (
        "tags = {'a', 'b'}\n"
        "prompt = ', '.join(tags)\n"
        "client.messages.create(model='m', messages=["
        "{'role': 'user', 'content': prompt}])\n"
    )
    target = tmp_path / "bom.py"
    target.write_bytes(b"\xef\xbb\xbf" + source.encode("utf-8"))

    diagnostics, errors = analyze_path_ex(target)

    assert errors == [], f"BOM file was rejected: {errors}"
    assert [d.rule_id for d in diagnostics] == ["PCL003"]


# --- the LLM sink must match the SDK call shapes, not substrings ----------

_TINTED_SYSTEM = '(model="m", system=f"Time: {datetime.now()}" ' \
                 '+ "STATIC RULES " * 30)\n'


@pytest.mark.parametrize("call", [
    "client.chat.completions.create",
    "client.chat.completions.parse",
    "client.beta.chat.completions.parse",
    "client.responses.create",
    "client.responses.parse",
    "client.responses.stream",
    "client.messages.create",
    "client.messages.stream",
    "client.chat.completions.stream",
    "client.beta.messages.create",
    "client.aio.messages.create",
    "AsyncAnthropic().messages.create",
    "get_client().chat.completions.create",
])
def test_pcl001_recognizes_sdk_call_shapes(call: str) -> None:
    """Every documented Anthropic/OpenAI entry point must be a prompt sink."""
    source = "from datetime import datetime\n" + call + _TINTED_SYSTEM
    assert "PCL001" in _codes(source), f"{call} was not treated as an LLM sink"


@pytest.mark.parametrize("call", [
    # "messages"/"create" appear as substrings, but the method is not one of
    # the SDK's terminal verbs -- substring matching used to fire on these.
    "self.messages_repo.create_user",
    "db.messages.create_index",
    "x.completions.recreate",
])
def test_plain_python_calls_are_not_llm_sinks(call: str) -> None:
    """A local object with a coincidental name must not be judged as a sink."""
    source = "from datetime import datetime\n" + call + _TINTED_SYSTEM
    assert _codes(source) == [], f"{call} was wrongly treated as an LLM sink"


# --- P1-5: taint sources, resolved through the file's own imports ---------

def _prefix_codes(header: str, value_expr: str) -> list:
    """Rule ids when ``value_expr`` is bound to ``v`` at the head of a system."""
    source = (
        header + "\n"
        "v = " + value_expr + "\n"
        'client.messages.create(model="m", '
        'system=f"{v}" + "STATIC RULES " * 30)\n'
    )
    return _codes(source)


@pytest.mark.parametrize("header,call", [
    ("from datetime import datetime as dt", "dt.now()"),
    ("import random as rnd", "rnd.choice(['a', 'b'])"),
    ("from uuid import uuid4 as u", "u()"),
    ("from random import choice", "choice(['a', 'b'])"),
    ("from uuid import uuid4", "uuid4()"),
])
def test_taint_source_resolved_through_an_import_alias(header, call) -> None:
    """The local spelling has to be expanded back to the module it came from."""
    assert "PCL001" in _prefix_codes(header, call), f"{header}: {call}"


@pytest.mark.parametrize("header,call", [
    ("import uuid", "uuid.uuid6()"),
    ("import uuid", "uuid.uuid7()"),
    ("import random", "random.uniform(0.0, 1.0)"),
    ("import random", "random.getrandbits(8)"),
    ("from datetime import datetime", "datetime.today()"),
    ("from datetime import datetime", "datetime.now(tz=None)"),
    ("import time", "time.strftime('%Y-%m-%d')"),
    ("import time", "time.ctime()"),
    ("import time", "time.localtime()"),
    ("import time", "time.gmtime()"),
    ("from django.utils import timezone", "timezone.now()"),
    ("import django.utils.timezone", "django.utils.timezone.now()"),
    ("import pandas as pd", "pd.Timestamp.now()"),
])
def test_previously_undetected_taint_source(header, call) -> None:
    assert "PCL001" in _prefix_codes(header, call), f"{header}: {call}"


@pytest.mark.parametrize("header,call", [
    # An explicit point in time makes these pure functions of their argument.
    ("import time", "time.strftime('%Y', (2024, 1, 1, 0, 0, 0, 0, 1, 0))"),
    ("import time", "time.ctime(0)"),
    ("import time", "time.localtime(0)"),
    ("import time", "time.gmtime(0)"),
    # hash() of a number is stable; only str/bytes are salted by
    # PYTHONHASHSEED.
    ("", "hash(42)"),
    ("n = 5", "hash(n)"),
])
def test_deterministic_calls_are_not_taint_sources(header, call) -> None:
    assert "PCL001" not in _prefix_codes(header, call), f"{header}: {call}"


@pytest.mark.parametrize("header,call", [
    ("name = 'alice'", "hash(name)"),
    ("", "hash('literal')"),
    ("msg = 'hi'", 'hash(f"{msg}")'),
])
def test_hash_of_a_string_is_a_taint_source(header, call) -> None:
    assert "PCL001" in _prefix_codes(header, call), f"{header}: {call}"


@pytest.mark.parametrize("header,call", [
    ("", "event.time()"),
    ("", "choice(options)"),
])
def test_names_that_only_look_like_taint_sources(header, call) -> None:
    """Neither `event.time` nor an unimported `choice` is a stdlib source."""
    assert _prefix_codes(header, call) == [], f"{header}: {call}"


def test_random_shuffle_taints_its_argument() -> None:
    """shuffle() reorders in place, so the argument stops being stable."""
    source = (
        "import random\n"
        "items = ['a', 'b']\n"
        "random.shuffle(items)\n"
        'client.messages.create(model="m", '
        'system=", ".join(items) + "STATIC RULES " * 30)\n'
    )
    assert "PCL001" in _codes(source)


# --- P1-6: match, except* and with bodies --------------------------------

def test_taint_assigned_inside_a_match_case() -> None:
    """ast.match_case is not an ast.stmt, so its body was never walked."""
    source = (
        "from datetime import datetime\n"
        "kind = 'a'\n"
        "match kind:\n"
        "    case 'a':\n"
        '        stamp = f"{datetime.now()}"\n'
        '    case _:\n'
        '        stamp = "static"\n'
        'client.messages.create(model="m", '
        'system=stamp + "STATIC RULES " * 30)\n'
    )
    assert "PCL001" in _codes(source)


def test_irrefutable_case_drops_the_taint_it_rebinds() -> None:
    """`case _` always runs, so the pre-match state cannot survive it."""
    source = (
        "from datetime import datetime\n"
        'stamp = f"{datetime.now()}"\n'
        "match kind:\n"
        '    case _:\n'
        '        stamp = "static"\n'
        'client.messages.create(model="m", '
        'system=stamp + "STATIC RULES " * 30)\n'
    )
    assert _codes(source) == [], _codes(source)


def test_partial_case_keeps_the_taint_it_may_not_rebind() -> None:
    """With no `case _`, the match may match nothing at all."""
    source = (
        "from datetime import datetime\n"
        'stamp = f"{datetime.now()}"\n'
        "match kind:\n"
        '    case "a":\n'
        '        stamp = "static"\n'
        'client.messages.create(model="m", '
        'system=stamp + "STATIC RULES " * 30)\n'
    )
    assert "PCL001" in _codes(source)


@pytest.mark.skipif(sys.version_info < (3, 11),
                    reason="except* requires Python 3.11+")
def test_taint_assigned_inside_an_except_star_handler() -> None:
    """ast.TryStar is not an ast.Try, so its handlers were never walked."""
    source = (
        "from datetime import datetime\n"
        'stamp = "static"\n'
        "try:\n"
        "    pass\n"
        "except* ValueError:\n"
        '    stamp = f"{datetime.now()}"\n'
        'client.messages.create(model="m", '
        'system=stamp + "STATIC RULES " * 30)\n'
    )
    assert "PCL001" in _codes(source)


def test_taint_assigned_inside_a_with_block() -> None:
    """Guard: With bodies go through the generic path and must keep working."""
    source = (
        "from datetime import datetime\n"
        'with open("f.txt") as handle:\n'
        '    stamp = f"{datetime.now()}"\n'
        'client.messages.create(model="m", '
        'system=stamp + "STATIC RULES " * 30)\n'
    )
    assert "PCL001" in _codes(source)


def test_tools_appended_inside_a_match_case_are_flagged() -> None:
    """A case arm only runs on some paths, exactly like an if arm."""
    source = (
        "kind = 'a'\n"
        "tools = [{'name': 't1'}]\n"
        "match kind:\n"
        "    case 'a':\n"
        "        tools.append({'name': 't2'})\n"
        "client.messages.create(model='m', messages=[], tools=tools)\n"
    )
    assert "PCL004" in _codes(source)


# --- P1-7: a static-sounding name must still be a static value -----------

def test_uppercase_name_bound_to_a_dynamic_value_is_not_static() -> None:
    """PREFIX = str(uuid.uuid4()) is dynamic however it is spelled.

    This is P1-7's acceptance test and it passed before any change: taint is
    checked ahead of the solid test, so a tainted name never reaches
    STATIC_PREFIX_NAMES. Kept as the guard it is.
    """
    source = (
        "import uuid\n"
        "PREFIX = str(uuid.uuid4())\n"
        'client.messages.create(model="m", '
        'system=PREFIX + "STATIC RULES " * 30)\n'
    )
    assert "PCL001" in _codes(source)


def test_header_bound_to_unknown_data_is_kept_static_on_purpose() -> None:
    """Known gap, left alone deliberately (P1-7, verify first).

    `HEADER = request.headers["x"]` is dynamic but carries no taint source,
    so the name list still calls it a solid and the taint after it is
    written off. Closing that means treating *any* assigned-but-unrecorded
    upper-case name as non-static, which turns `SYSTEM_PROMPT =
    build_prompt()` into a PCL001 error everywhere -- and
    test_pcl001_still_spared_by_a_listed_static_prefix_name pins the
    opposite behaviour. Raised rather than guessed at.
    """
    source = (
        "from datetime import datetime\n"
        'HEADER = request.headers["x"]\n'
        'client.messages.create(model="m", '
        'system=HEADER + " | " + f"{datetime.now()}")\n'
    )
    assert _codes(source) == [], _codes(source)


def test_uppercase_name_bound_to_a_string_is_still_static() -> None:
    """Guard: a literal assigned to STATIC_RULES keeps its solid."""
    source = (
        'STATIC_RULES = "Be helpful."\n'
        "from datetime import datetime\n"
        'client.messages.create(model="m", '
        'system=STATIC_RULES + f"{datetime.now()}")\n'
    )
    assert _codes(source) == [], _codes(source)


def test_unassigned_uppercase_name_is_still_static() -> None:
    """Guard: the name list still speaks for names this file never assigns."""
    source = (
        "from datetime import datetime\n"
        'system = KNOWLEDGE_BASE + f"{datetime.now()}"\n'
        'client.messages.create(model="m", system=system)\n'
    )
    assert _codes(source) == [], _codes(source)


# --- P2-1: Anthropic caches only up to a cache_control breakpoint ---------

_CACHED_SYSTEM_BLOCK = (
    "from datetime import datetime\n"
    "STATIC_RULES = 'rules ' * 30\n"
    "client.messages.create(\n"
    '    model="m",\n'
    "    system=[{'type': 'text',\n"
    "             'text': STATIC_RULES + f'{datetime.now()}',\n"
    "             'cache_control': {'type': 'ephemeral'}}],\n"
    "    messages=[{'role': 'user', 'content': 'hi'}],\n"
    ")\n"
)

_NO_BREAKPOINT = (
    "from datetime import datetime\n"
    "STATIC_RULES = 'rules ' * 30\n"
    "client.messages.create(\n"
    '    model="m",\n'
    "    system=[{'type': 'text',\n"
    "             'text': STATIC_RULES + f'{datetime.now()}'}],\n"
    "    messages=[{'role': 'user', 'content': 'hi'}],\n"
    ")\n"
)

_OPENAI_SINK = (
    "from datetime import datetime\n"
    "STATIC_RULES = 'rules ' * 30\n"
    "client.chat.completions.create(\n"
    '    model="m",\n'
    "    messages=[{'role': 'system',\n"
    "               'content': STATIC_RULES + f'{datetime.now()}',\n"
    "               'cache_control': {'type': 'ephemeral'}}],\n"
    ")\n"
)

_TAINT_AFTER_BREAKPOINT = (
    "from datetime import datetime\n"
    "STATIC_RULES = 'rules ' * 30\n"
    "client.messages.create(\n"
    '    model="m",\n'
    "    system=[{'type': 'text', 'text': STATIC_RULES,\n"
    "             'cache_control': {'type': 'ephemeral'}}],\n"
    "    messages=[{'role': 'user', 'content': f'{datetime.now()}'}],\n"
    ")\n"
)


def test_pcl005_taint_inside_a_cached_block_is_a_total_miss() -> None:
    """Static first, taint last -- PCL001 calls that a partial hit.

    Anthropic hits only when every byte up to the breakpoint is identical,
    so this is a 100% miss and PCL001's ordering test never sees it.
    """
    assert "PCL005" in _codes(_CACHED_SYSTEM_BLOCK), _codes(_CACHED_SYSTEM_BLOCK)


def test_pcl005_fires_on_the_anthropic_stream_endpoint() -> None:
    source = _CACHED_SYSTEM_BLOCK.replace("client.messages.create(",
                                          "client.messages.stream(")
    assert "PCL005" in _codes(source), _codes(source)


def test_pcl005_needs_a_cache_breakpoint() -> None:
    """Without cache_control nothing is cached, so nothing is invalidated."""
    assert _codes(_NO_BREAKPOINT) == [], _codes(_NO_BREAKPOINT)


def test_pcl005_is_not_applied_to_openai_sinks() -> None:
    """OpenAI caches the longest matching prefix, so taint at the end is fine."""
    assert _codes(_OPENAI_SINK) == [], _codes(_OPENAI_SINK)


def test_pcl005_ignores_taint_after_the_last_breakpoint() -> None:
    """Only the bytes up to the breakpoint have to match exactly."""
    assert "PCL005" not in _codes(_TAINT_AFTER_BREAKPOINT), \
        _codes(_TAINT_AFTER_BREAKPOINT)


def test_pcl005_is_an_error_with_no_autofix() -> None:
    """Where the dynamic value goes is a design decision, not a rewrite."""
    found = [d for d in analyze_code(_CACHED_SYSTEM_BLOCK, "case.py")
             if d.rule_id == "PCL005"]
    assert len(found) == 1, f"expected exactly one PCL005, got {found}"
    assert found[0].severity == "ERROR"
    assert found[0].edits == ()


def test_pcl005_is_a_known_rule_id_with_a_description() -> None:
    """Selectors, disable comments and the SARIF rule table all key off these."""
    from pcdlint.rules import KNOWN_RULE_IDS, RULE_SHORT_DESCRIPTIONS

    assert "PCL005" in KNOWN_RULE_IDS
    assert RULE_SHORT_DESCRIPTIONS["PCL005"]


# --- P2-3: marks set by pass 0 must survive pass 1 ------------------------

def test_pcl004_survives_a_second_tracking_pass() -> None:
    """A def forces pass 2, and pass 2 rebinds tools before the append.

    The append mark is set on pass 0 only, so the reassignment wiped it and
    the tools list looked untouched.
    """
    source = (
        "def helper():\n"
        "    return {'name': 'c'}\n"
        "tools = [{'name': 'a'}]\n"
        "if cond:\n"
        "    tools.append({'name': 'b'})\n"
        "client.messages.create(model='m', messages=[], tools=tools)\n"
    )
    assert "PCL004" in _codes(source), _codes(source)


def test_pcl001_from_an_augmented_assignment_survives_a_second_pass() -> None:
    """prompt = SYSTEM_PROMPT clears the taint the earlier += had added."""
    source = (
        "from datetime import datetime\n"
        "SYSTEM_PROMPT = 'rules ' * 30\n"
        "def helper():\n"
        "    return 1\n"
        "prompt = SYSTEM_PROMPT\n"
        "prompt += f'{datetime.now()}'\n"
        "client.messages.create(model='m', system=prompt, messages=[])\n"
    )
    assert "PCL001" in _codes(source), _codes(source)
