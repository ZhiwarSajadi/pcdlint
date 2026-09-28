"""Regression tests for correctness/robustness fixes (see audit findings)."""

import textwrap

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
