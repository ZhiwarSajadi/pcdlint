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
        blob = json.dumps(records)
        SYSTEM_PROMPT = "head " * 50 + blob
        client.messages.create(model="m", system=SYSTEM_PROMPT)
    '''
    assert "PCL002" in _codes(source)


def test_pcl002_ignores_dumps_that_never_reach_a_prompt() -> None:
    source = '''
        import json
        cache = json.dumps(records)
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
            {"role": "user", "content": json.dumps(records)}])
    '''
    assert _codes(source) == ["PCL002"]


def test_pcl002_sees_a_dumps_imported_by_name() -> None:
    """The tracker accepts bare ``dumps`` but the rule demanded ``json.dumps``,
    so the provenance was recorded and then never reported."""
    source = '''
        from json import dumps
        payload = dumps(records)
        client.messages.create(model="m", messages=[
            {"role": "user", "content": payload}])
    '''
    assert _codes(source) == ["PCL002"]


def test_pcl002_still_silent_when_the_payload_never_reaches_a_prompt() -> None:
    source = '''
        import json
        audit = json.dumps(records)
        print(audit)
    '''
    assert _codes(source) == []


def test_pcl002_sees_dumps_through_a_module_alias() -> None:
    """``import json as J`` spells the same non-determinism as ``json.dumps``."""
    source = '''
        import json as J
        payload = J.dumps(records)
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
    for name in (".pytest_cache", ".mypy_cache", "site-packages", "htmlcov"):
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


# --- P2-2: judge the value the call used, not the final one ---------------

def test_pcl001_sees_the_value_the_call_actually_used() -> None:
    """p holds a tainted prefix when the call runs and a static one after.

    Tracking finishes before any rule runs, so the rule used to read p's
    *final* value and the call looked clean.
    """
    source = (
        "from datetime import datetime\n"
        "SYSTEM_PROMPT = 'rules ' * 30\n"
        "p = f'{datetime.now()}' + SYSTEM_PROMPT\n"
        "client.messages.create(model='m', system=p, messages=[])\n"
        "p = SYSTEM_PROMPT\n"
    )
    assert "PCL001" in _codes(source), _codes(source)


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


def test_a_call_inside_a_function_still_sees_module_data_defined_after_it() -> None:
    """A function's execution point is unknowable, so it keeps the whole-file view.

    Freezing at the `def` would be wrong -- the module-level `p` below does
    not exist yet when the body is walked.
    """
    source = (
        "from datetime import datetime\n"
        "def handler(client):\n"
        "    client.messages.create(model='m', system=p, messages=[])\n"
        "p = f'{datetime.now()}' + 'STATIC RULES ' * 30\n"
    )
    assert "PCL001" in _codes(source), _codes(source)


# --- P2-4: PCL002's wording must not overstate the risk -------------------

def test_pcl002_wording_is_honest_about_dict_order() -> None:
    """CPython dicts keep insertion order, so an unsorted dumps is only
    non-deterministic when the dict's build order varies -- merges, sets,
    DB rows, ** spreads. Calling it flatly non-deterministic was wrong."""
    source = (
        "import json\n"
        "prompt = json.dumps(payload)\n"
        "client.messages.create(model='m', "
        "messages=[{'role': 'user', 'content': prompt}])\n"
    )
    found = [d for d in analyze_code(source, "case.py")
             if d.rule_id == "PCL002"]
    assert len(found) == 1, f"expected one PCL002, got {found}"
    assert found[0].severity == "WARNING"
    assert "depends on how the dict was built" in found[0].message, \
        found[0].message
    assert "sort_keys=True" in found[0].fix_suggestion


# --- P2-5: README claims that are not true -------------------------------

def test_readme_examples_use_a_cache_capable_model() -> None:
    """`gpt-4` predates prompt caching, so the example it shows never caches.

    The README is the first thing a reader copies from, and it also has to
    keep explaining why OpenAI and Anthropic disagree about what a hit is.
    """
    from pathlib import Path

    readme = Path(__file__).resolve().parents[1] / "README.md"
    text = readme.read_text(encoding="utf-8")

    assert 'model="gpt-4"' not in text, "gpt-4 does not support prompt caching"
    assert "10x read discount" not in text, "discount varies by provider/model"
    assert "cache_control" in text, "the provider contrast section must stay"


# --- P3-1: reachability is only worth probing where it can matter --------

def test_reachability_is_only_probed_for_nodes_that_can_match() -> None:
    """_check_pcl003 asked _reaches_prompt about *every* node in the file.

    Each call walked every entry of tracker.json_flows, so the cost grew
    with the file and the flow table on nodes that could never match -- an
    int, a plain call, a constant.
    """
    from pcdlint.rules import RuleEngine

    probed: list = []
    original = RuleEngine._reaches_prompt

    def counting(self, node):
        probed.append(node)
        return original(self, node)

    source = (
        "from datetime import datetime\n"
        "a = datetime.now()\n"
        "b = f'{a}'\n"
        "c = 'x' + 'y'\n"
        "d = len(c)\n"
        "client.messages.create(model='m', system=b, messages=[])\n"
    )
    RuleEngine._reaches_prompt = counting
    try:
        analyze_code(source, "case.py")
    finally:
        RuleEngine._reaches_prompt = original

    assert probed == [], (
        f"_reaches_prompt was probed {len(probed)} times on code with no set "
        "iteration and no json.dumps"
    )


# --- P3-6: workflow actions must not float -------------------------------

def test_every_workflow_action_is_pinned_to_a_commit_sha() -> None:
    """A tag is a movable pointer: whoever owns the repo can retarget it.

    Dependabot keeps SHA pins updated, so pinning costs nothing after the
    first time.
    """
    import re
    from pathlib import Path

    root = Path(__file__).resolve().parents[1]
    pinned = 0
    for workflow in sorted((root / ".github" / "workflows").glob("*.yml")):
        text = workflow.read_text(encoding="utf-8")
        for lineno, line in enumerate(text.splitlines(), 1):
            match = re.search(r"uses:\s*\S+@(\S+)", line)
            if match is None:
                continue
            ref = match.group(1)
            assert re.fullmatch(r"[0-9a-f]{40}", ref), (
                f"{workflow.name}:{lineno} uses '@{ref}', a movable ref"
            )
            pinned += 1

    assert pinned >= 8, f"expected the workflows' actions, found {pinned}"


# --- R-01: an internal error must never look like a finding --------------

def test_r01_deep_concatenation_is_analyzed_not_crashed() -> None:
    """A left-nested ``+`` chain is legal Python, so analyzing it must work.

    1,000 terms used to blow the stack in taint.py's recursive helpers and
    escape as an uncaught ``RecursionError`` -> exit 1, which the exit-code
    contract reserves for "findings".
    """
    from pcdlint.analyzer import analyze_code_ex

    terms = " + ".join(['"a"'] * 3000)
    source = (
        'from datetime import datetime\n'
        'STATIC_RULES = "rule " * 100\n'
        f"x = {terms}\n"
        'client.messages.create(model="m", max_tokens=1, system=x, messages=[])\n'
    )
    diagnostics, error = analyze_code_ex(source, "deep.py")
    assert error is None, error
    assert diagnostics == []

def test_r01_internal_error_exits_2_and_names_the_file(
    tmp_path, monkeypatch, capsys: pytest.CaptureFixture
) -> None:
    """A rule raising is an analyzer fault: exit 2, one line, no traceback."""
    from pcdlint import analyzer
    from pcdlint.cli import main

    target = tmp_path / "boom.py"
    target.write_text('x = "a"\n', encoding="utf-8")

    def boom(*_args, **_kwargs):
        raise ValueError("synthetic failure")

    monkeypatch.setattr(analyzer.RuleEngine, "run", boom)
    monkeypatch.setattr(sys, "argv", ["pcdlint", "check", str(target)])

    assert main() == 2

    captured = capsys.readouterr()
    assert "Traceback" not in captured.err, captured.err
    assert target.name in captured.err, captured.err
    assert "ValueError" in captured.err, captured.err


# --- R-02: text already bound to the name is preceding text --------------

def test_r02_aug_assign_after_static_prefix_is_clean() -> None:
    """`prompt = STATIC; prompt += f"{taint}"` is the README's good ordering."""
    source = '''
        from datetime import datetime
        STATIC_RULES = "rule " * 100
        prompt = STATIC_RULES
        prompt += f"\\nTime: {datetime.now()}"
        client.chat.completions.create(model="m",
            messages=[{"role": "system", "content": prompt}])
    '''
    assert _codes(source) == []

def test_r02_reassign_after_static_prefix_is_clean() -> None:
    """`prompt = prompt + f"{taint}"` puts the dynamic value last too."""
    source = '''
        from datetime import datetime
        prompt = "rule " * 100
        prompt = prompt + f"\\nTime: {datetime.now()}"
        client.chat.completions.create(model="m",
            messages=[{"role": "system", "content": prompt}])
    '''
    assert _codes(source) == []

def test_r02_taint_first_still_flagged() -> None:
    """Taint bound before the static block must still be reported."""
    source = '''
        from datetime import datetime
        prompt = f"{datetime.now()}\\n"
        prompt += STATIC_RULES
        client.chat.completions.create(model="m",
            messages=[{"role": "system", "content": prompt}])
    '''
    assert _codes(source) == ["PCL001"]

def test_r02_taint_before_static_on_reassign_still_flagged() -> None:
    """Same, through `prompt = f"...{taint}..." + prompt`."""
    source = '''
        from datetime import datetime
        STATIC_RULES = "rule " * 100
        prompt = STATIC_RULES
        prompt = f"{datetime.now()}\\n" + prompt
        client.chat.completions.create(model="m",
            messages=[{"role": "system", "content": prompt}])
    '''
    assert _codes(source) == ["PCL001"]


# --- R-03: messages[0] is a user turn when system= is separate -----------

def test_r03_static_system_kwarg_dynamic_first_user_message_is_clean() -> None:
    """Anthropic puts the system prompt in its own argument, so messages[0]
    comes *after* it -- and the README says to move dynamic values there."""
    source = '''
        from datetime import datetime
        client.messages.create(model="m", max_tokens=1, system=STATIC_RULES,
            messages=[{"role": "user",
                       "content": f"Now: {datetime.now()}. Question?"}])
    '''
    assert _codes(source) == []

def test_r03_user_message_in_variable_with_static_system_is_clean() -> None:
    """Same, with the user message built into a variable first."""
    source = '''
        from datetime import datetime
        question = f"Now: {datetime.now()}. Question?"
        client.messages.create(model="m", max_tokens=1, system=STATIC_RULES,
            messages=[{"role": "user", "content": question}])
    '''
    assert _codes(source) == []

def test_r03_dynamic_user_first_without_system_still_flagged() -> None:
    """No separate system argument: messages[0] *is* the prompt prefix."""
    source = '''
        from datetime import datetime
        client.chat.completions.create(model="m",
            messages=[{"role": "user",
                       "content": f"{datetime.now()} " + STATIC_RULES}])
    '''
    assert _codes(source) == ["PCL001"]

def test_r03_cache_control_keeps_the_first_message_a_prefix() -> None:
    """A breakpoint on the message makes everything before it part of the
    cached prefix, separate system= or not. PCL005 reports the same miss
    from the breakpoint's side."""
    source = '''
        from datetime import datetime
        client.messages.create(model="m", max_tokens=1, system=STATIC_RULES,
            messages=[{"role": "user", "cache_control": {"type": "ephemeral"},
                       "content": f"{datetime.now()} "}])
    '''
    assert _codes(source) == ["PCL001", "PCL005"]


# --- R-04: the name heuristic needs an LLM in the file -------------------

def test_r04_prompt_named_vars_with_no_llm_call_are_clean() -> None:
    """`context`/`system_info` in a file that never mentions an LLM is not
    prompt material -- and PCL003 is an ERROR carrying an autofix, so it can
    fail a build over code it has no business judging."""
    source = '''
        tags = {"a", "b"}
        context = ", ".join(tags)
        system_info = ", ".join(tags)
        print(context, system_info)
    '''
    assert _codes(source) == []

def test_r04_prompt_named_var_feeding_a_sink_still_reports() -> None:
    """The same code, with the value actually passed as the system prompt."""
    source = '''
        tags = {"a", "b"}
        context = ", ".join(tags)
        client.messages.create(model="m", max_tokens=1, system=context,
            messages=[])
    '''
    assert _codes(source) == ["PCL003"]

def test_r04_prompt_named_var_in_a_file_importing_an_llm_still_reports() -> None:
    """An SDK import is evidence the file deals with prompts even before a
    call site shows up."""
    source = '''
        import anthropic
        tags = {"a", "b"}
        context = ", ".join(tags)
        print(context)
    '''
    assert _codes(source) == ["PCL003"]


# --- R-05: the dotted path alone does not make a sink --------------------

def test_r05_twilio_style_messages_create_is_not_a_sink() -> None:
    """`twilio.messages.create(body=...)` reads as `.messages.create` but
    sends a text message, not a prompt."""
    source = '''
        import json
        tags = {"a", "b"}
        twilio.messages.create(body=", ".join(tags), from_="+1", to="+2")
        twilio.messages.create(body=json.dumps({"a": 1}), from_="+1", to="+2")
    '''
    assert _codes(source) == []

def test_r05_sink_without_a_model_keyword_still_reports() -> None:
    """A payload keyword on its own is enough: the model may come from the
    client, and the legacy positional form has no keywords at all."""
    source = '''
        from datetime import datetime
        client.messages.create(
            messages=[{"role": "system", "content": f"Time: {datetime.now()}"}])
    '''
    assert _codes(source) == ["PCL001"]


# --- R-06: a literal cannot have an unstable key order -------------------

_R06_TAIL = '''
        client.messages.create(model="m", max_tokens=1, system=system, messages=[])
    '''

def test_r06_literal_dict_is_not_reported() -> None:
    """A dict literal is insertion-ordered: its order is the source order."""
    source = '''
        import json
        system = STATIC_RULES + json.dumps({"b": 1, "a": 2})
    ''' + _R06_TAIL
    assert _codes(source) == []

def test_r06_literal_list_is_not_reported() -> None:
    """sort_keys does nothing to a list, so asking for it is meaningless."""
    source = '''
        import json
        system = STATIC_RULES + json.dumps(["b", "a"])
    ''' + _R06_TAIL
    assert _codes(source) == []

def test_r06_unknown_input_still_reported() -> None:
    """A name's dict came from somewhere the analyzer cannot see."""
    source = '''
        import json
        system = STATIC_RULES + json.dumps(some_var)
    ''' + _R06_TAIL
    assert _codes(source) == ["PCL002"]

def test_r06_double_star_spread_still_reported() -> None:
    """`**` merges at runtime, so the final order is not the source order."""
    source = '''
        import json
        system = STATIC_RULES + json.dumps({**base, "a": 1})
    ''' + _R06_TAIL
    assert _codes(source) == ["PCL002"]

def test_r06_comprehension_still_reported() -> None:
    """A comprehension iterates something whose order is unknown."""
    source = '''
        import json
        system = STATIC_RULES + json.dumps({k: v for k, v in rows})
    ''' + _R06_TAIL
    assert _codes(source) == ["PCL002"]


# --- R-07: tracking must never edit the tree it was handed ---------------

def test_r07_append_after_the_call_is_not_seen_by_it() -> None:
    """The call ran before the append, so it never saw that element."""
    source = '''
        from datetime import datetime
        messages = [{"role": "system", "content": STATIC_RULES}]
        client.chat.completions.create(model="m", messages=messages)
        messages.append({"role": "system",
                         "content": f"{datetime.now()} {STATIC_RULES}"})
    '''
    assert _codes(source) == []

def test_r07_extend_after_the_call_is_not_seen_by_it() -> None:
    """Same for extend()."""
    source = '''
        from datetime import datetime
        messages = [{"role": "system", "content": STATIC_RULES}]
        client.chat.completions.create(model="m", messages=messages)
        messages.extend([{"role": "system",
                          "content": f"{datetime.now()} {STATIC_RULES}"}])
    '''
    assert _codes(source) == []

def test_r07_append_before_the_call_still_reports() -> None:
    """Reversed order: the element really is in the list the call reads."""
    source = '''
        from datetime import datetime
        messages = [{"role": "system", "content": STATIC_RULES}]
        messages.append({"role": "system",
                         "content": f"{datetime.now()} {STATIC_RULES}"})
        client.chat.completions.create(model="m", messages=messages)
    '''
    assert _codes(source) == ["PCL001"]

def test_r07_tracking_does_not_modify_the_parsed_tree() -> None:
    """Snapshots are shallow copies of the bindings, so a mutated ast.List
    is visible to every snapshot at once -- and to the rule's own walks."""
    import ast

    from pcdlint.analyzer import _track_tree
    from pcdlint.taint import TaintTracker

    source = (
        "from datetime import datetime\n"
        "messages = [{'role': 'system', 'content': STATIC_RULES}]\n"
        "messages.append({'role': 'user', 'content': 'x'})\n"
        "messages.extend([{'role': 'user', 'content': 'y'}])\n"
        "client.chat.completions.create(model='m', messages=messages)\n"
        "tools = [{'name': 'a'}]\n"
        "tools.append({'name': 'b'})\n"
    )
    tree = ast.parse(source)
    before = ast.dump(tree)
    tracker = TaintTracker()
    tracker.build_scopes(tree)
    _track_tree(tracker, tree)
    assert ast.dump(tree) == before


# --- R-08: a path may follow an option ----------------------------------

_R08_BUG = (
    "from datetime import datetime\n"
    "client.messages.create(model=\"m\", max_tokens=1,\n"
    "    system=f\"{datetime.now()} \" + \"rule \" * 100, messages=[])\n"
)

def test_r08_paths_after_an_option_are_all_analyzed(tmp_path, monkeypatch,
                                                    capsys) -> None:
    """argparse does not interleave a `paths` positional with options by
    default, so `check first --fail-on-warn second` rejected `second` and
    exited 2 -- "a path could not be analyzed", for a path it never tried."""
    (tmp_path / "first").mkdir()
    (tmp_path / "second").mkdir()
    (tmp_path / "first" / "one.py").write_text(_R08_BUG, encoding="utf-8")
    (tmp_path / "second" / "two.py").write_text(_R08_BUG, encoding="utf-8")
    monkeypatch.chdir(tmp_path)

    code = _run_cli("check", "first", "--fail-on-warn", "second")

    out = capsys.readouterr().out
    assert code == 1, out
    assert "one.py" in out and "two.py" in out, out


# --- R-09: a finding must survive being piped ----------------------------

def test_r09_a_long_path_is_not_wrapped_when_stdout_is_piped(tmp_path) -> None:
    """rich hard-wraps at 80 columns when stdout is not a TTY, splitting
    `path:line:col` across lines -- which breaks grep, editors and GitHub
    problem matchers."""
    import re
    import subprocess
    import sys as _sys

    directory = tmp_path / ("d" * 40) / ("e" * 40)
    directory.mkdir(parents=True)
    target = directory / "module.py"
    target.write_text(_R08_BUG, encoding="utf-8")

    proc = subprocess.run(
        [_sys.executable, "-m", "pcdlint.cli", "check", str(target)],
        capture_output=True, text=True, encoding="utf-8", check=False,
    )

    assert proc.returncode == 1, proc.stderr
    finding = next(line for line in proc.stdout.splitlines()
                   if "PCL001" in line)
    assert str(target) in finding, finding
    assert re.search(r":\d+:\d+\s", finding), finding


# --- R-10: which directories a walk silently skips -----------------------

def _r10_walk(tmp_path, monkeypatch, capsys, folder: str) -> str:
    # Scan the parent: a path named on the command line is never filtered,
    # so passing `folder` directly would bypass SKIP_DIRS entirely.
    (tmp_path / folder).mkdir()
    (tmp_path / folder / "mod.py").write_text(_R08_BUG, encoding="utf-8")
    monkeypatch.chdir(tmp_path)
    code = _run_cli("check", ".")
    return f"code={code} out={capsys.readouterr().out}"

def test_r10_env_directory_is_scanned(tmp_path, monkeypatch, capsys) -> None:
    """`env` is a common name for application code, not just a virtualenv.
    Real virtualenvs are already caught by the pyvenv.cfg rule, which does
    not depend on what the folder happens to be called."""
    assert "mod.py" in _r10_walk(tmp_path, monkeypatch, capsys, "env")

def test_r10_build_and_dist_stay_skipped(tmp_path, monkeypatch, capsys) -> None:
    """Packaging output. Documented in the README rather than discovered
    by finding your source silently absent from a run."""
    assert "mod.py" not in _r10_walk(tmp_path, monkeypatch, capsys, "build")
    assert "mod.py" not in _r10_walk(tmp_path, monkeypatch, capsys, "dist")


# --- R-11: overlapping paths must not double-report ----------------------

def test_r11_overlapping_paths_report_each_finding_once(tmp_path, monkeypatch,
                                                        capsys) -> None:
    """`check app app/mod.py` analysed the same file twice and printed the
    same finding twice -- which doubles every count a consumer reads."""
    import json

    (tmp_path / "app").mkdir()
    (tmp_path / "app" / "mod.py").write_text(_R08_BUG, encoding="utf-8")
    monkeypatch.chdir(tmp_path)

    code = _run_cli("check", "app", "app/mod.py", "--format", "json")

    assert code == 1
    found = json.loads(capsys.readouterr().out)
    keys = [(d["file_path"], d["lineno"], d["col_offset"], d["rule_id"])
            for d in found]
    assert len(keys) == len(set(keys)), keys


# --- R-12: the linted file's own warnings are not our output -------------

def test_r12_syntax_warnings_from_the_linted_file_do_not_reach_stderr(
        tmp_path) -> None:
    """`re.compile("\\d+")` makes ast.parse emit a SyntaxWarning about the
    user's code, so a normal run printed a warning on stderr that has
    nothing to do with pcdlint."""
    import subprocess
    import sys as _sys

    target = tmp_path / "warned.py"
    target.write_text('import re\npattern = re.compile("\\d+")\n',
                      encoding="utf-8")

    proc = subprocess.run(
        [_sys.executable, "-m", "pcdlint.cli", "check", str(target)],
        capture_output=True, text=True, encoding="utf-8", check=False,
    )

    assert proc.returncode in (0, 1), proc.stderr
    assert "SyntaxWarning" not in proc.stderr, proc.stderr
    assert proc.stderr.strip() == "", proc.stderr


# --- R-13: line numbers must be Python's, not str.splitlines()' ----------

_R13_BASE = (
    "import json\n"
    "from datetime import datetime\n"
    "# pcdlint: disable\n"
    'client.messages.create(model="m", max_tokens=1,\n'
    '    system=f"{datetime.now()} " + "rule " * 100, messages=[])\n'
)

def test_r13_suppression_survives_a_form_feed_earlier_in_the_file() -> None:
    """`str.splitlines()` also breaks on form feed, \\v, \\x85, U+2028 and
    U+2029. The tokenizer does not, so after one of those every marker below
    it maps to the wrong line -- and a suppression moved is a suppression
    that silently stops applying."""
    plain = [d.rule_id for d in analyze_code(_R13_BASE, "case.py")]
    shifted = [d.rule_id for d in analyze_code(
        _R13_BASE.replace("import json", "import json\ns = 'a\x0cb'", 1),
        "case.py",
    )]
    assert plain, "the fixture must report something for this to compare"
    assert shifted == plain

def test_r13_source_lines_match_python_line_numbering(tmp_path) -> None:
    """SARIF's column conversion reads `lines[lineno - 1]`, so one extra
    line in the split shifts every column below it onto the wrong line."""
    from pcdlint.cli import _read_source_lines

    target = tmp_path / "x.py"
    target.write_bytes(b"import json\ns = 'a\x0cb'\n# tail\n")

    assert _read_source_lines(str(target)) == (
        "import json", "s = 'a\x0cb'", "# tail",
    )

def test_r13_sarif_columns_survive_a_form_feed_earlier_in_the_file(
        tmp_path, monkeypatch, capsys) -> None:
    """endColumn is measured against `lines[end_lineno - 1]`. One line too
    many in the split points it at the line above, whose length decides the
    column -- so a form feed two hundred lines earlier moves a column."""
    import json

    def region(shifted: bool) -> dict:
        filler = "s = 'a\x0cb'" if shifted else "s = 'ab'"
        (tmp_path / "case.py").write_text(
            "import json\n"
            + filler + "\n"
            "from datetime import datetime\n"
            "if True:\n"
            '    client.messages.create(model="m", max_tokens=1, '
            'system=f"{datetime.now()} " + "rule " * 100, messages=[])\n',
            encoding="utf-8",
        )
        monkeypatch.chdir(tmp_path)
        assert _run_cli("check", "case.py", "--format", "sarif") == 1
        payload = json.loads(capsys.readouterr().out)
        loc = payload["runs"][0]["results"][0]["locations"][0]
        return loc["physicalLocation"]["region"]

    clean = region(False)
    assert region(True) == clean


# --- R-15: a request-level cache_control is still a breakpoint -----------

_R15_TAIL = (
    '    messages=[{"role": "user", "content": "hi"}],\n'
    ")\n"
)

def test_r15_request_level_cache_control_still_reports() -> None:
    """Anthropic's automatic caching puts one breakpoint at the request
    level, applying it to the last cacheable block -- so taint in `system`
    is still a total miss, and PCL005 looked only inside system/messages."""
    source = (
        "from datetime import datetime\n"
        'STATIC_RULES = "rules " * 30\n'
        "client.messages.create(\n"
        '    model="m",\n'
        '    cache_control={"type": "ephemeral"},\n'
        "    system=f'{STATIC_RULES} {datetime.now()}',\n"
        + _R15_TAIL
    )
    assert "PCL005" in _codes(source), _codes(source)

def test_r15_request_level_cache_control_with_a_clean_prompt_reports_nothing() -> None:
    """The breakpoint alone is not a finding; only taint before it is."""
    source = (
        "from datetime import datetime\n"
        'STATIC_RULES = "rules " * 30\n'
        "client.messages.create(\n"
        '    model="m",\n'
        '    cache_control={"type": "ephemeral"},\n'
        "    system=STATIC_RULES,\n"
        + _R15_TAIL
    )
    assert _codes(source) == [], _codes(source)

def test_r15_without_any_cache_control_reports_nothing() -> None:
    """PCL005 only exists when there is a breakpoint to invalidate."""
    source = (
        "from datetime import datetime\n"
        'STATIC_RULES = "rules " * 30\n'
        "client.messages.create(\n"
        '    model="m",\n'
        "    system=f'{STATIC_RULES} {datetime.now()}',\n"
        + _R15_TAIL
    )
    assert "PCL005" not in _codes(source), _codes(source)


# --- R-16: taint propagation gaps ----------------------------------------
# Each sub-item pairs a construct that is missed with a simpler control
# that is caught, so a failure names the construct rather than the harness.

def test_r16b_tuple_unpacking_carries_taint() -> None:
    """`system, user = f"...", "hi"` bound the taint to nothing: only plain
    `ast.Name` targets were tracked, so a tuple target was skipped whole."""
    source = '''
        from datetime import datetime
        system, user = f"T {datetime.now()}\\n{STATIC_RULES}", "hi"
        client.messages.create(model="m", max_tokens=1, system=system,
            messages=[{"role": "user", "content": user}])
    '''
    assert "PCL001" in _codes(source), _codes(source)

def test_r16b_list_unpacking_carries_taint() -> None:
    source = '''
        from datetime import datetime
        [system, user] = [f"T {datetime.now()}\\n{STATIC_RULES}", "hi"]
        client.messages.create(model="m", max_tokens=1, system=system,
            messages=[{"role": "user", "content": user}])
    '''
    assert "PCL001" in _codes(source), _codes(source)

def test_r16b_control_static_unpacking_reports_nothing() -> None:
    source = '''
        system, user = STATIC_RULES, "hi"
        client.messages.create(model="m", max_tokens=1, system=system,
            messages=[{"role": "user", "content": user}])
    '''
    assert "PCL001" not in _codes(source), _codes(source)

def _r16j_resolvers(expr: str):
    """``(origin, prefix)`` both resolvers give for `_value = <expr>`."""
    import ast as _ast

    from pcdlint.analyzer import _track_tree
    from pcdlint.taint import TaintTracker

    tree = _ast.parse("from datetime import datetime\n"
                      'ctx = {"t": datetime.now()}\n'
                      + f"_value = {expr}\n")
    tracker = TaintTracker()
    tracker.build_scopes(tree)
    _track_tree(tracker, tree)
    value = tree.body[-1].value
    return (tracker.get_taint_origin_of_node(value),
            tracker.get_prefix_tainted(value))

def test_r16j_inline_conditional_carries_taint() -> None:
    """`system=(f"..." if flag else STATIC)` inline in the call."""
    source = '''
        from datetime import datetime
        client.messages.create(model="m", max_tokens=1,
            system=(f"T {datetime.now()}\\n{STATIC_RULES}" if flag
                    else STATIC_RULES),
            messages=[])
    '''
    assert "PCL001" in _codes(source), _codes(source)

def test_r16j_both_resolvers_handle_the_same_shapes() -> None:
    """`get_prefix_tainted` and `get_taint_origin_of_node` answer the same
    question and duplicate most of their dispatch. Whichever gains a branch
    the other lacks silently drops findings -- which is exactly how an
    inline conditional went unreported."""
    shapes = [
        'f"{datetime.now()}\\n{STATIC_RULES}"',
        '(f"{datetime.now()}\\n{STATIC_RULES}" if flag else STATIC_RULES)',
        '(s := f"{datetime.now()}\\n{STATIC_RULES}")',
        'f"{datetime.now()}\\n" + STATIC_RULES',
        'str(int(time.time() * 1000)) + STATIC_RULES',
        '-int(time.time())',
        '[f"{datetime.now()}"]',
        '(f"{datetime.now()}", "hi")',
        'ctx["t"] + STATIC_RULES',
    ]
    for expr in shapes:
        origin, prefix = _r16j_resolvers(expr)
        assert origin is not None, f"origin resolver missed {expr}"
        assert prefix is not None, (
            f"prefix resolver lost a shape the origin resolver handles: {expr}"
        )

_R16A_TAIL = '''
                client.messages.create(model="m", max_tokens=1,
                    system=self.system, messages=[])
'''

def test_r16a_attribute_binding_reaches_the_prompt() -> None:
    """`self.system = f"..."` in __init__ and read in go(): only ast.Name
    targets were tracked, so the attribute bound nothing."""
    source = '''
        from datetime import datetime
        class PromptBuilder:
            def __init__(self):
                self.system = f"Time: {datetime.now()}\\n{STATIC_RULES}"
            def go(self):
''' + _R16A_TAIL + '''
        PromptBuilder().go()
    '''
    assert "PCL001" in _codes(source), _codes(source)

def test_r16a_control_static_attribute_reports_nothing() -> None:
    source = '''
        class PromptBuilder:
            def __init__(self):
                self.system = STATIC_RULES
            def go(self):
''' + _R16A_TAIL + '''
        PromptBuilder().go()
    '''
    assert "PCL001" not in _codes(source), _codes(source)

def test_r16a_attribute_bindings_do_not_leak_between_classes() -> None:
    """Class scope, not method scope, is the binding's home -- and it has to
    stop at the class, or one class's timestamp answers for another."""
    source = '''
        from datetime import datetime
        class Clean:
            def __init__(self):
                self.system = STATIC_RULES
            def go(self):
''' + _R16A_TAIL + '''
        class Tainted:
            def __init__(self):
                self.system = f"Time: {datetime.now()}\\n{STATIC_RULES}"
            def go(self):
''' + _R16A_TAIL + '''
        Clean().go()
        Tainted().go()
    '''
    assert _codes(source) == ["PCL001"], _codes(source)

def test_r16d_tainted_argument_reaches_the_prompt_through_a_helper() -> None:
    """`def build(ts): return f"...{ts}..."` called as `build(datetime.now())`.
    The summary only recorded a *statically* known return origin, and a
    parameter has none."""
    source = '''
        from datetime import datetime
        def build(ts):
            return f"Time: {ts}\\n{STATIC_RULES}"
        system = build(datetime.now())
        client.messages.create(model="m", max_tokens=1, system=system,
            messages=[])
    '''
    assert "PCL001" in _codes(source), _codes(source)

def test_r16d_tainted_keyword_argument_reaches_the_prompt() -> None:
    source = '''
        from datetime import datetime
        def build(ts):
            return f"Time: {ts}\\n{STATIC_RULES}"
        system = build(ts=datetime.now())
        client.messages.create(model="m", max_tokens=1, system=system,
            messages=[])
    '''
    assert "PCL001" in _codes(source), _codes(source)

def test_r16d_control_helper_that_ignores_its_argument_reports_nothing() -> None:
    """Guards the other direction: passing a timestamp to a helper that
    never uses it must not taint the result."""
    source = '''
        from datetime import datetime
        def build(ts):
            return f"Time: {STATIC_RULES}"
        system = build(datetime.now())
        client.messages.create(model="m", max_tokens=1, system=system,
            messages=[])
    '''
    assert "PCL001" not in _codes(source), _codes(source)

def test_r16f_awaited_taint_reaches_the_prompt() -> None:
    source = '''
        import asyncio
        from datetime import datetime
        async def build():
            return f"Time: {datetime.now()}\\n{STATIC_RULES}"
        async def main():
            system = await build()
            client.messages.create(model="m", max_tokens=1, system=system,
                messages=[])
        asyncio.run(main())
    '''
    assert "PCL001" in _codes(source), _codes(source)

def test_r16g_taint_survives_multiplication() -> None:
    """`int(time.time() * 1000)` is a timestamp; the multiplication does not
    make it deterministic."""
    source = '''
        import time
        rid = int(time.time() * 1000)
        system = f"Request {rid}\\n{STATIC_RULES}"
        client.messages.create(model="m", max_tokens=1, system=system,
            messages=[])
    '''
    assert "PCL001" in _codes(source), _codes(source)

def test_r16g_taint_survives_a_unary_operator() -> None:
    source = '''
        import time
        rid = -int(time.time())
        system = f"Request {rid}\\n{STATIC_RULES}"
        client.messages.create(model="m", max_tokens=1, system=system,
            messages=[])
    '''
    assert "PCL001" in _codes(source), _codes(source)

def test_r16h_taint_survives_percent_formatting() -> None:
    """`"Time: %s\\n" % datetime.now()` is the old spelling of an f-string."""
    source = '''
        from datetime import datetime
        system = "Time: %s\\n" % datetime.now() + STATIC_RULES
        client.messages.create(model="m", max_tokens=1, system=system,
            messages=[])
    '''
    assert "PCL001" in _codes(source), _codes(source)

def test_r16h_control_percent_with_no_taint_reports_nothing() -> None:
    source = '''
        system = "Time: %s\\n" % STATIC_RULES
        client.messages.create(model="m", max_tokens=1, system=system,
            messages=[])
    '''
    assert "PCL001" not in _codes(source), _codes(source)

def test_r16c_named_expression_carries_taint() -> None:
    """`system=(s := f"...")` is one expression; the walrus is not a value
    of its own, it is its target."""
    source = '''
        from datetime import datetime
        client.messages.create(model="m", max_tokens=1,
            system=(s := f"T {datetime.now()}\\n{STATIC_RULES}"),
            messages=[])
    '''
    assert "PCL001" in _codes(source), _codes(source)

def test_r16c_named_expression_without_taint_reports_nothing() -> None:
    source = '''
        client.messages.create(model="m", max_tokens=1,
            system=(s := STATIC_RULES),
            messages=[])
    '''
    assert "PCL001" not in _codes(source), _codes(source)

def test_r16i_subscript_into_a_tainted_dict_carries_taint() -> None:
    """The key does not make the value constant: `ctx['t']` is whatever was
    put in `ctx['t']`."""
    source = '''
        from datetime import datetime
        ctx = {"t": datetime.now()}
        system = f"Time: {ctx['t']}\\n{STATIC_RULES}"
        client.messages.create(model="m", max_tokens=1, system=system,
            messages=[])
    '''
    assert "PCL001" in _codes(source), _codes(source)

def test_r16i_subscript_into_a_static_dict_reports_nothing() -> None:
    source = '''
        ctx = {"t": STATIC_RULES}
        system = f"Time: {ctx['t']}\\n{STATIC_RULES}"
        client.messages.create(model="m", max_tokens=1, system=system,
            messages=[])
    '''
    assert "PCL001" not in _codes(source), _codes(source)

def test_r16i_subscript_of_a_static_key_in_a_mixed_dict_reports_nothing() -> None:
    """Precision: `ctx['static']` does not go dynamic because some other
    key in the same dict holds the time."""
    source = '''
        from datetime import datetime
        ctx = {"static": STATIC_RULES, "t": datetime.now()}
        system = f"Time: {ctx['static']}\\n{STATIC_RULES}"
        client.messages.create(model="m", max_tokens=1, system=system,
            messages=[])
    '''
    assert "PCL001" not in _codes(source), _codes(source)
    source = '''
        import time
        rid = int(time.time())
        system = f"Request {rid}\\n{STATIC_RULES}"
        client.messages.create(model="m", max_tokens=1, system=system,
            messages=[])
    '''
    assert "PCL001" in _codes(source), _codes(source)
    source = '''
        from datetime import datetime
        def build():
            return f"Time: {datetime.now()}\\n{STATIC_RULES}"
        system = build()
        client.messages.create(model="m", max_tokens=1, system=system,
            messages=[])
    '''
    assert "PCL001" in _codes(source), _codes(source)
