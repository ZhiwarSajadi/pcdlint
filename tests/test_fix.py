"""Autofix spans: PCL002 gets sort_keys, PCL003 gets sorted(...)."""

from pcdlint.analyzer import analyze_code
from pcdlint.models import Diagnostic, TextEdit

PCL002_TAIL = (
    "client.messages.create(model='m', messages=["
    "{'role': 'user', 'content': prompt}])\n"
)


def _edits(source: str, rule_id: str) -> list:
    """The single diagnostic of ``rule_id`` plus its fix edits."""
    found = [d for d in analyze_code(source) if d.rule_id == rule_id]
    assert len(found) == 1, (
        f"expected one {rule_id}, got {[d.rule_id for d in analyze_code(source)]}"
    )
    assert found[0].edits, f"{rule_id} reported a fix but attached no edits"
    return list(found[0].edits)


def _line(source: str, line_no: int) -> bytes:
    """One line of ``source`` as UTF-8, so column assertions are byte-exact."""
    return source.split("\n")[line_no - 1].encode("utf-8")


def _pcl002_source(dumps_call: str) -> str:
    return "import json\nprompt = " + dumps_call + "\n" + PCL002_TAIL


# --- PCL002: add sort_keys=True -----------------------------------------

def test_pcl002_edit_inserts_sort_keys() -> None:
    source = _pcl002_source("json.dumps(payload)")
    (edit,) = _edits(source, "PCL002")
    assert edit.replacement == ", sort_keys=True"
    assert (edit.start_line, edit.start_col) == (edit.end_line, edit.end_col)
    assert b")" in _line(source, 2)[edit.start_col:]


def test_pcl002_edit_after_trailing_comma_needs_no_second_comma() -> None:
    source = _pcl002_source("json.dumps(payload,)")
    (edit,) = _edits(source, "PCL002")
    assert edit.replacement == ", sort_keys=True"
    assert (edit.start_line, edit.start_col) == (edit.end_line, edit.end_col)
    assert b")" in _line(source, 2)[edit.start_col:]


def test_pcl002_edit_on_empty_call_is_bare_keyword() -> None:
    source = _pcl002_source("json.dumps()")
    (edit,) = _edits(source, "PCL002")
    # No arguments means no comma to lead with, and no room before the paren.
    assert edit.replacement == "sort_keys=True"
    assert (edit.start_line, edit.start_col) == (edit.end_line, edit.end_col)
    assert _line(source, 2)[:edit.start_col].endswith(b"(")


def test_pcl002_edit_replaces_existing_false_value() -> None:
    source = _pcl002_source("json.dumps(payload, sort_keys=False)")
    (edit,) = _edits(source, "PCL002")
    # Overwriting the value avoids a duplicate keyword argument.
    assert edit.replacement == "True"
    assert edit.start_col != edit.end_col
    line = _line(source, 2)
    assert line[:edit.start_col].endswith(b"sort_keys=")
    assert line[edit.start_col:edit.end_col] == b"False"


def test_pcl002_declines_a_call_that_unpacks_kwargs() -> None:
    """**opts may already carry sort_keys, so appending one is unsafe.

    ``json.dumps(payload, **opts, sort_keys=True)`` parses fine -- the
    post-fix ast.parse guard cannot see it -- and raises
    ``TypeError: got multiple values for keyword argument 'sort_keys'``
    whenever opts happens to define that key. The finding stands; the
    rewrite does not.
    """
    source = _pcl002_source("json.dumps(payload, **opts)")
    found = [d for d in analyze_code(source) if d.rule_id == "PCL002"]
    assert len(found) == 1, (
        f"expected one PCL002, got {[d.rule_id for d in analyze_code(source)]}"
    )
    assert found[0].edits == (), "a **kwargs splat must not be rewritten"


def test_cli_fix_leaves_a_kwargs_unpacking_call_byte_identical(
        tmp_path, monkeypatch) -> None:
    """--fix must report the finding and write nothing back."""
    source = _pcl002_source("json.dumps(payload, **opts)")
    target = tmp_path / "sample.py"
    # Bytes, so the comparison is about the fix and not about whether
    # write_text translated \n to \r\n on this platform.
    target.write_bytes(source.encode("utf-8"))
    monkeypatch.chdir(tmp_path)

    (code,) = _run_cli(["check", "sample.py", "--fix", "--fail-on-warn"])

    assert target.read_bytes() == source.encode("utf-8")
    assert code == 1, "the PCL002 warning must still be reported"


# --- PCL003: wrap the set in sorted(...) --------------------------------

def _pcl003_edits(expression: str, argument: bytes) -> list:
    source = (
        "tags = {'a', 'b'}\n"
        f"prompt = {expression}\n"
        + PCL002_TAIL
    )
    edits = _edits(source, "PCL003")
    assert len(edits) == 2, f"expected an open and a close, got {edits}"
    opening = [e for e in edits if e.replacement == "sorted("]
    closing = [e for e in edits if e.replacement == ")"]
    assert len(opening) == 1 and len(closing) == 1, edits
    open_e, close_e = opening[0], closing[0]
    # Both edits are pure insertions that bracket the argument exactly.
    assert (open_e.start_line, open_e.start_col) == (open_e.end_line, open_e.end_col)
    assert (close_e.start_line, close_e.start_col) == (close_e.end_line, close_e.end_col)
    assert (open_e.start_line, open_e.start_col) < (close_e.end_line, close_e.end_col)
    assert _line(source, open_e.start_line)[open_e.start_col:close_e.end_col] == argument
    return edits


def test_pcl003_edit_wraps_join_argument() -> None:
    _pcl003_edits("', '.join(tags)", b"tags")


def test_pcl003_edit_wraps_str_argument() -> None:
    _pcl003_edits("str(tags)", b"tags")


def test_pcl003_edit_wraps_fstring_value() -> None:
    _pcl003_edits('f"{tags}"', b"tags")


def test_pcl003_edit_wraps_fstring_value_before_conversion() -> None:
    # The conversion lives outside the value node, so it must survive.
    _pcl003_edits('f"{tags!r}"', b"tags")


# --- rules with no mechanical fix ---------------------------------------

def test_pcl001_and_pcl004_attach_no_edits() -> None:
    source = (
        "from datetime import datetime\n"
        "system = f'{datetime.now()} ' + 'STATIC RULES ' * 30\n"
        "tools = {'a', 'b'}\n"
        "client.messages.create(model='m', system=system, messages=[], tools=tools)\n"
    )
    for diagnostic in analyze_code(source):
        assert diagnostic.edits == (), (
            f"{diagnostic.rule_id} has no mechanical fix but attached edits"
        )


# --- applying the edits --------------------------------------------------

def test_apply_edits_renders_sort_keys_fix() -> None:
    from pcdlint.fixer import apply_edits

    source = _pcl002_source("json.dumps(payload)")
    fixed = apply_edits(source, _edits(source, "PCL002"))
    assert "json.dumps(payload, sort_keys=True)" in fixed
    assert "PCL002" not in [d.rule_id for d in analyze_code(fixed)]


def test_apply_edits_renders_trailing_comma_call() -> None:
    from pcdlint.fixer import apply_edits

    source = _pcl002_source("json.dumps(payload,)")
    fixed = apply_edits(source, _edits(source, "PCL002"))
    assert "json.dumps(payload, sort_keys=True,)" in fixed
    assert "PCL002" not in [d.rule_id for d in analyze_code(fixed)]


def test_apply_edits_renders_sorted_wrap() -> None:
    from pcdlint.fixer import apply_edits

    # The sink is required: since R-04 a prompt-shaped name in a file with
    # no LLM call is just a name, and this test is about the rewrite, not
    # about when PCL003 decides to fire.
    source = ("tags = {'a', 'b'}\nprompt = ', '.join(tags)\n" + PCL002_TAIL)
    fixed = apply_edits(source, _edits(source, "PCL003"))
    assert "prompt = ', '.join(sorted(tags))" in fixed
    assert "PCL003" not in [d.rule_id for d in analyze_code(fixed)]


def test_apply_edits_keeps_multibyte_columns_intact() -> None:
    """ast.col_offset counts UTF-8 bytes, so splicing must too."""
    from pcdlint.fixer import apply_edits

    source = (
        "import json\n"
        "prompt = 'héllo' + json.dumps(payload)\n"
        + PCL002_TAIL
    )
    fixed = apply_edits(source, _edits(source, "PCL002"))
    assert "json.dumps(payload, sort_keys=True)" in fixed
    assert "héllo" in fixed


def test_apply_edits_drops_overlapping_edits() -> None:
    from pcdlint.fixer import apply_edits

    source = "hello world\n"
    overlapping = (TextEdit(1, 0, 1, 5, "X"), TextEdit(1, 3, 1, 8, "Y"))
    assert apply_edits(source, overlapping) == "X world\n"


def test_apply_edits_without_edits_returns_source_unchanged() -> None:
    from pcdlint.fixer import apply_edits

    source = "x = 1\n"
    assert apply_edits(source, []) == source


# --- --fix through the CLI ----------------------------------------------

def _run_cli(argv: list) -> tuple:
    import sys

    from pcdlint.cli import main

    old_argv = sys.argv
    try:
        sys.argv = ["pcdlint", *argv]
        return (main(),)
    finally:
        sys.argv = old_argv


def test_cli_fix_rewrites_file_and_reports_clean(tmp_path, monkeypatch) -> None:
    target = tmp_path / "sample.py"
    target.write_text(_pcl002_source("json.dumps(payload)"), encoding="utf-8")
    monkeypatch.chdir(tmp_path)

    (code,) = _run_cli(["check", "sample.py", "--fix"])

    written = target.read_text(encoding="utf-8")
    assert "json.dumps(payload, sort_keys=True)" in written
    assert "PCL002" not in [d.rule_id for d in analyze_code(written)]
    assert code == 0


def test_cli_fix_leaves_unfixable_finding_and_exits_1(tmp_path, monkeypatch) -> None:
    source = (
        "from datetime import datetime\n"
        "system = f'{datetime.now()} ' + 'STATIC RULES ' * 30\n"
        "client.messages.create(model='m', system=system, messages=[])\n"
    )
    target = tmp_path / "sample.py"
    target.write_text(source, encoding="utf-8")
    monkeypatch.chdir(tmp_path)

    (code,) = _run_cli(["check", "sample.py", "--fix"])

    assert target.read_text(encoding="utf-8") == source
    assert code == 1


def test_apply_fix_refuses_a_rewrite_that_no_longer_parses(tmp_path) -> None:
    """A fix that breaks the file is reported, never written."""
    from pcdlint.cli import _apply_fixes

    target = tmp_path / "sample.py"
    target.write_text("x = 1\n", encoding="utf-8")
    broken = Diagnostic(
        file_path=str(target), lineno=1, col_offset=0, rule_id="PCL002",
        rule_name="unsorted-json-in-prefix", message="m",
        fix_suggestion="f", severity="WARNING",
        edits=(TextEdit(1, 0, 1, 0, "def broken("),),
    )

    changed, _skipped, errors = _apply_fixes([broken])

    assert changed == 0
    assert errors and "invalid syntax" in errors[0]
    assert target.read_text(encoding="utf-8") == "x = 1\n"


def test_cli_fix_reports_findings_it_could_not_fix(tmp_path, monkeypatch,
                                                   capsys) -> None:
    import sys

    from pcdlint.cli import main

    source = (
        "from datetime import datetime\n"
        "system = f'{datetime.now()} ' + 'STATIC RULES ' * 30\n"
        "client.messages.create(model='m', system=system, messages=[])\n"
    )
    target = tmp_path / "sample.py"
    target.write_text(source, encoding="utf-8")
    monkeypatch.chdir(tmp_path)

    old_argv = sys.argv
    try:
        sys.argv = ["pcdlint", "check", "sample.py", "--fix"]
        main()
        err = capsys.readouterr().err
    finally:
        sys.argv = old_argv

    assert "fixed 0 file(s)" in err
    assert "1 finding(s) have no automatic fix" in err


def test_cli_fix_leaves_line_endings_alone(tmp_path, monkeypatch) -> None:
    """--fix rewrites a file; it must not also rewrite its newlines.

    read_text()/write_text() translate through os.linesep, so on Windows an
    LF-authored file comes back CRLF and shows up in git as a whole-file diff.
    """
    target = tmp_path / "sample.py"
    target.write_bytes(_pcl002_source("json.dumps(payload)").encode("utf-8"))
    monkeypatch.chdir(tmp_path)

    (code,) = _run_cli(["check", "sample.py", "--fix"])

    fixed = target.read_bytes()
    assert b"\r" not in fixed, "--fix converted LF line endings to CRLF"
    assert b"sort_keys=True" in fixed
    assert code == 0


def test_cli_fix_keeps_crlf_line_endings_crlf(tmp_path, monkeypatch) -> None:
    target = tmp_path / "sample.py"
    crlf = _pcl002_source("json.dumps(payload)").replace("\n", "\r\n")
    target.write_bytes(crlf.encode("utf-8"))
    monkeypatch.chdir(tmp_path)

    (code,) = _run_cli(["check", "sample.py", "--fix"])

    fixed = target.read_bytes()
    assert fixed.count(b"\r\n") == crlf.count("\r\n")
    assert b"sort_keys=True" in fixed
    assert code == 0


def test_cli_fix_declines_a_set_whose_elements_cannot_be_ordered(
        tmp_path, monkeypatch, capsys) -> None:
    """sorted() on mixed types raises TypeError -- a fix must not ship one."""
    import sys

    from pcdlint.cli import main

    source = "tags = {1, 'a'}\nprompt = ', '.join(tags)\n" + PCL002_TAIL
    target = tmp_path / "sample.py"
    target.write_bytes(source.encode("utf-8"))
    monkeypatch.chdir(tmp_path)

    old_argv = sys.argv
    try:
        sys.argv = ["pcdlint", "check", "sample.py", "--fix"]
        code = main()
        err = capsys.readouterr().err
    finally:
        sys.argv = old_argv

    assert target.read_bytes() == source.encode("utf-8"), (
        "--fix wrapped the set in sorted(), which raises on {1, 'a'}"
    )
    assert "no automatic fix" in err
    assert code == 1


def test_cli_fix_still_repairs_a_set_of_strings(tmp_path, monkeypatch) -> None:
    """The narrowing rule must not take the common case with it."""
    target = tmp_path / "sample.py"
    source = "tags = {'b', 'a'}\nprompt = ', '.join(tags)\n" + PCL002_TAIL
    target.write_bytes(source.encode("utf-8"))
    monkeypatch.chdir(tmp_path)

    (code,) = _run_cli(["check", "sample.py", "--fix"])

    assert b"sorted(tags)" in target.read_bytes()
    assert code == 0
