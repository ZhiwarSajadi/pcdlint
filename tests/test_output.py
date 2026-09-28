"""Machine-readable output formats: SARIF for GitHub Code Scanning."""

import json
import sys

import pytest

from pcdlint.cli import main

# PCL001 (ERROR) and PCL002 (WARNING) both fire on this file.
SAMPLE = (
    "import json\n"
    "from datetime import datetime\n"
    "system = f'{datetime.now()} ' + 'STATIC RULES ' * 30\n"
    "prompt = json.dumps(payload)\n"
    "client.messages.create(model='m', system=system, "
    "messages=[{'role': 'user', 'content': prompt}])\n"
)


def _run_cli(argv: list, capsys: pytest.CaptureFixture) -> tuple:
    old_argv = sys.argv
    try:
        sys.argv = ["pcdlint", *argv]
        code = main()
        captured = capsys.readouterr()
        return code, captured.out, captured.err
    finally:
        sys.argv = old_argv


def _sarif(capsys: pytest.CaptureFixture, argv: list) -> dict:
    code, out, _err = _run_cli(argv, capsys)
    assert code in (0, 1), f"unexpected exit {code}"
    return json.loads(out)


def _write(tmp_path, monkeypatch) -> None:
    target = tmp_path / "sample.py"
    target.write_text(SAMPLE, encoding="utf-8")
    monkeypatch.chdir(tmp_path)


def test_sarif_has_the_required_envelope(tmp_path, monkeypatch, capsys) -> None:
    _write(tmp_path, monkeypatch)
    data = _sarif(capsys, ["check", "sample.py", "--format", "sarif"])
    assert data["version"] == "2.1.0"
    assert data["$schema"].endswith("sarif-2.1.0.json")
    driver = data["runs"][0]["tool"]["driver"]
    assert driver["name"] == "pcdlint"
    assert "version" in driver
    assert "informationUri" in driver


def test_sarif_lists_every_known_rule(tmp_path, monkeypatch, capsys) -> None:
    _write(tmp_path, monkeypatch)
    data = _sarif(capsys, ["check", "sample.py", "--format", "sarif"])
    rules = data["runs"][0]["tool"]["driver"]["rules"]
    assert {r["id"] for r in rules} == {"PCL001", "PCL002", "PCL003",
                                        "PCL004", "PCL005"}
    for rule in rules:
        assert rule["shortDescription"]["text"]
        assert rule["helpUri"]


def test_sarif_maps_severity_to_level(tmp_path, monkeypatch, capsys) -> None:
    _write(tmp_path, monkeypatch)
    data = _sarif(capsys, ["check", "sample.py", "--format", "sarif"])
    levels = {r["level"] for r in data["runs"][0]["results"]}
    assert levels == {"error", "warning"}, levels


def test_sarif_reports_position_and_message(tmp_path, monkeypatch, capsys) -> None:
    _write(tmp_path, monkeypatch)
    data = _sarif(capsys, ["check", "sample.py", "--format", "sarif"])
    results = data["runs"][0]["results"]
    assert results
    for result in results:
        assert result["ruleId"].startswith("PCL")
        assert result["message"]["text"]
        region = result["locations"][0]["physicalLocation"]["region"]
        assert isinstance(region["startLine"], int) and region["startLine"] >= 1
        assert isinstance(region["startColumn"], int) and region["startColumn"] >= 1


def test_sarif_paths_are_posix_relative_uris(tmp_path, monkeypatch, capsys) -> None:
    nested = tmp_path / "pkg"
    nested.mkdir()
    (nested / "mod.py").write_text(SAMPLE, encoding="utf-8")
    monkeypatch.chdir(tmp_path)

    data = _sarif(capsys, ["check", "pkg", "--format", "sarif"])

    results = data["runs"][0]["results"]
    assert results, "expected findings inside the nested module"
    for result in results:
        uri = result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
        assert "\\" not in uri, uri
        assert uri == "pkg/mod.py", uri


def test_sarif_exit_code_matches_json(tmp_path, monkeypatch, capsys) -> None:
    _write(tmp_path, monkeypatch)
    sarif_code, _out, _err = _run_cli(
        ["check", "sample.py", "--format", "sarif"], capsys)
    json_code, _out, _err = _run_cli(
        ["check", "sample.py", "--format", "json"], capsys)
    assert sarif_code == json_code == 1


# --- --diff: only report what changed -----------------------------------

# A finding is reported when the line it points at changed, so the taint and
# the call that consumes it are deliberately on one line here: PCL001 reports
# the position where the dynamic value reaches the prompt.
CLEAN = (
    "import json\n"
    "from datetime import datetime\n"
    "client.messages.create(model='m', system='STATIC RULES ' * 30, messages=[])\n"
)

BUGGY = (
    "import json\n"
    "from datetime import datetime\n"
    "client.messages.create(model='m', "
    "system=f'{datetime.now()} ' + 'STATIC RULES ' * 30, messages=[])\n"
)


def _git(args: list, cwd) -> None:
    import subprocess

    subprocess.run(["git", *args], cwd=cwd, capture_output=True,
                   text=True, check=True)


def _repo(tmp_path, monkeypatch, initial: str) -> None:
    monkeypatch.chdir(tmp_path)
    _git(["init", "-q"], tmp_path)
    _git(["config", "user.email", "test@example.com"], tmp_path)
    _git(["config", "user.name", "Test"], tmp_path)
    (tmp_path / "sample.py").write_text(initial, encoding="utf-8")
    _git(["add", "."], tmp_path)
    _git(["commit", "-q", "-m", "base"], tmp_path)


def test_diff_reports_findings_on_newly_changed_lines(tmp_path, monkeypatch,
                                                      capsys) -> None:
    _repo(tmp_path, monkeypatch, CLEAN)
    # Line 3 changes and becomes the line the finding sits on.
    (tmp_path / "sample.py").write_text(BUGGY, encoding="utf-8")

    code, out, _err = _run_cli(["check", "sample.py", "--diff"], capsys)

    assert code == 1, out
    assert "PCL001" in out
    assert ":3:" in out, out


def test_diff_hides_findings_on_untouched_lines(tmp_path, monkeypatch,
                                                capsys) -> None:
    _repo(tmp_path, monkeypatch, BUGGY)
    # Only line 1 changes; the PCL001 finding lives on line 3.
    (tmp_path / "sample.py").write_text(
        BUGGY.replace("import json\n", "import json  # touched\n"),
        encoding="utf-8")

    code, out, _err = _run_cli(["check", "sample.py", "--diff"], capsys)

    assert code == 0, out
    assert "PCL001" not in out


def test_diff_with_clean_tree_reports_nothing(tmp_path, monkeypatch,
                                              capsys) -> None:
    _repo(tmp_path, monkeypatch, BUGGY)

    code, out, _err = _run_cli(["check", "sample.py", "--diff"], capsys)

    assert code == 0, out
    assert "PCL001" not in out


def test_diff_with_unknown_ref_exits_2(tmp_path, monkeypatch, capsys) -> None:
    _repo(tmp_path, monkeypatch, BUGGY)

    code, _out, err = _run_cli(
        ["check", "sample.py", "--diff", "no-such-ref"], capsys)

    assert code == 2
    assert "git" in err.lower()


def test_diff_accepts_an_explicit_ref(tmp_path, monkeypatch, capsys) -> None:
    _repo(tmp_path, monkeypatch, CLEAN)
    (tmp_path / "sample.py").write_text(BUGGY, encoding="utf-8")
    _git(["add", "."], tmp_path)
    _git(["commit", "-q", "-m", "buggy"], tmp_path)

    # Diff the first commit against the working tree, not the default HEAD.
    code, out, _err = _run_cli(["check", "sample.py", "--diff", "HEAD~1"], capsys)

    assert code == 1, out
    assert "PCL001" in out


def test_diff_reports_findings_in_an_untracked_new_file(tmp_path, monkeypatch,
                                                        capsys) -> None:
    """``git diff REF`` never lists a file nobody has added.

    A brand-new file therefore came back "no findings, exit 0" under --diff
    -- a clean-looking run for the one file the change just introduced.
    """
    _repo(tmp_path, monkeypatch, CLEAN)
    (tmp_path / "new_file.py").write_text(BUGGY, encoding="utf-8")

    code, out, _err = _run_cli(["check", "new_file.py", "--diff"], capsys)

    assert code == 1, out
    assert "PCL001" in out


def test_diff_still_hides_findings_in_an_ignored_file(tmp_path, monkeypatch,
                                                      capsys) -> None:
    """Guard: .gitignore'd files are not part of the change either."""
    _repo(tmp_path, monkeypatch, CLEAN)
    (tmp_path / ".gitignore").write_text("scratch.py\n", encoding="utf-8")
    _git(["add", "."], tmp_path)
    _git(["commit", "-q", "-m", "ignore"], tmp_path)
    (tmp_path / "scratch.py").write_text(BUGGY, encoding="utf-8")

    code, _out, _err = _run_cli(["check", "scratch.py", "--diff"], capsys)

    assert code == 0


def test_diff_exits_2_when_git_cannot_run_at_all(tmp_path, monkeypatch,
                                                 capsys) -> None:
    """git missing must not read as "no changed lines, no findings"."""
    from pcdlint import cli

    _repo(tmp_path, monkeypatch, CLEAN)
    (tmp_path / "sample.py").write_text(BUGGY, encoding="utf-8")

    class _NoGit:
        @staticmethod
        def run(*_args, **_kwargs):
            raise OSError("git is not installed")

    monkeypatch.setattr(cli, "subprocess", _NoGit())

    code, _out, err = _run_cli(["check", "sample.py", "--diff"], capsys)

    assert code == 2
    assert "git" in err.lower()


def test_diff_parser_skips_malformed_hunk_headers() -> None:
    """A hunk header git never emits must be dropped, not raise."""
    from pathlib import Path

    from pcdlint.cli import _parse_added_lines

    root = Path.cwd().resolve()
    patch = (
        "+++ sample.py\n"
        "@@ -1,2\n"              # truncated
        "@@ -1,2 @@\n"           # no new-file range
        "@@ -1,2 +nope,3 @@\n"   # not a number
        "@@ -1,2 +3,1 @@\n"      # the only valid header
    )

    assert _parse_added_lines(patch, root) == {
        (root / "sample.py").resolve().as_posix(): {3}
    }


# --- --fix combined with --diff ------------------------------------------

# Line 3 carries an unfixable PCL001; line 4 a fixable PCL002. Only line 4
# is touched by the change under review.
MIXED = (
    "import json\n"
    "from datetime import datetime\n"
    "client.messages.create(model='m', "
    "system=f'{datetime.now()} ' + 'STATIC RULES ' * 30, messages=[])\n"
    "prompt = json.dumps({'b': 1, 'a': 2})\n"
)

MIXED_CHANGED = MIXED.replace("{'b': 1, 'a': 2}", "{'b': 1, 'a': 2, 'c': 3}")


def test_fix_with_diff_reports_only_the_changed_line(tmp_path, monkeypatch,
                                                     capsys) -> None:
    """--fix re-analyses after rewriting; the diff filter must survive it.

    Without re-applying the filter the exit code described every finding in
    the touched file rather than every finding the change introduced, so an
    untouched PCL001 on line 3 turned a clean diff run into exit 1.
    """
    _repo(tmp_path, monkeypatch, MIXED)
    (tmp_path / "sample.py").write_text(MIXED_CHANGED, encoding="utf-8")

    code, out, _err = _run_cli(["check", "sample.py", "--fix", "--diff"], capsys)

    assert "sort_keys=True" in (tmp_path / "sample.py").read_text(encoding="utf-8")
    assert code == 0, out
    assert "PCL001" not in out, out


def test_fix_with_diff_still_fails_on_a_changed_unfixable_finding(
        tmp_path, monkeypatch, capsys) -> None:
    """Guard: re-applying the filter must not hide a finding on a changed line."""
    _repo(tmp_path, monkeypatch, CLEAN)
    (tmp_path / "sample.py").write_text(BUGGY, encoding="utf-8")

    code, out, _err = _run_cli(["check", "sample.py", "--fix", "--diff"], capsys)

    assert code == 1, out
    assert "PCL001" in out


ACCENTED = "café.py"


def test_diff_reports_findings_on_a_changed_line_in_an_accented_file(
        tmp_path, monkeypatch, capsys) -> None:
    """git octal-quotes non-ASCII paths in diff headers by default.

    ``+++ "caf\\303\\251.py"`` never matches the real path, so every finding
    in the file was dropped and the run reported clean.
    """
    _repo(tmp_path, monkeypatch, CLEAN)
    (tmp_path / ACCENTED).write_text(CLEAN, encoding="utf-8")
    _git(["add", "."], tmp_path)
    _git(["commit", "-q", "-m", "accents"], tmp_path)
    (tmp_path / ACCENTED).write_text(BUGGY, encoding="utf-8")

    code, out, _err = _run_cli(["check", ACCENTED, "--diff"], capsys)

    assert code == 1, out
    assert "PCL001" in out


def test_diff_reports_findings_in_an_untracked_accented_file(tmp_path,
                                                             monkeypatch,
                                                             capsys) -> None:
    """Untracked listing must survive the same quoting rules."""
    _repo(tmp_path, monkeypatch, CLEAN)
    (tmp_path / ACCENTED).write_text(BUGGY, encoding="utf-8")

    code, out, _err = _run_cli(["check", ACCENTED, "--diff"], capsys)

    assert code == 1, out
    assert "PCL001" in out


def test_diff_parser_does_not_take_an_added_line_for_a_file_header() -> None:
    """An added line whose text is "++ foo" is rendered as "+++ foo".

    Read as a file header it steals every later hunk, so the findings those
    hunks describe are credited to a file that does not exist and dropped.
    """
    from pathlib import Path

    from pcdlint.cli import _parse_added_lines

    root = Path.cwd().resolve()
    # --no-prefix, so the header carries the plain path the findings use.
    patch = (
        "--- one.py\n"
        "+++ one.py\n"
        "@@ -1,1 +1,3 @@\n"
        "-one\n"
        "+one\n"
        "+++ foo\n"           # added line; its text is "++ foo"
        "+bar\n"
        "@@ -9,1 +11,2 @@\n"
        "-two\n"
        "+two\n"
        "+extra\n"
    )

    assert _parse_added_lines(patch, root) == {
        (root / "one.py").resolve().as_posix(): {1, 2, 3, 11, 12}
    }


def test_diff_parser_does_not_take_a_removed_line_for_a_file_header() -> None:
    """A removed line whose text is "-- x" renders as "--- x".

    It must not start a new file section: the added line that follows it
    ("++ y" -> "+++ y") belongs to the same hunk, not to a file called y.
    """
    from pathlib import Path

    from pcdlint.cli import _parse_added_lines

    root = Path.cwd().resolve()
    patch = (
        "--- one.py\n"
        "+++ one.py\n"
        "@@ -1,1 +1,2 @@\n"
        "--- x\n"             # removed line; its text is "-- x"
        "+++ y\n"             # added line; its text is "++ y"
        "+z\n"
        "@@ -9,1 +11,1 @@\n"
        "-old\n"
        "+new\n"
    )

    assert _parse_added_lines(patch, root) == {
        (root / "one.py").resolve().as_posix(): {1, 2, 11}
    }


def test_sarif_uri_keeps_a_path_outside_the_working_tree(tmp_path,
                                                         monkeypatch) -> None:
    """Code Scanning wants a relative URI, but a path it cannot relativize
    must survive as given rather than crash or be dropped."""
    from pathlib import Path

    from pcdlint.cli import _sarif_uri

    monkeypatch.chdir(tmp_path)
    outside = Path(Path.cwd().anchor) / "somewhere" / "other.py"

    assert _sarif_uri(str(outside)) == outside.as_posix()


# --- P3-3: SARIF fidelity -------------------------------------------------

# `é` is 2 UTF-8 bytes but 1 UTF-16 unit, and it sits before the reported
# column, so the two counts disagree by one on this line.
_NON_ASCII = (
    "from datetime import datetime\n"
    "client.messages.create(model='é', "
    "system=f'{datetime.now()}' + 'STATIC RULES ' * 30, messages=[])\n"
)


def test_sarif_columns_count_utf16_units(tmp_path, monkeypatch, capsys) -> None:
    """ast's col_offset counts UTF-8 bytes; SARIF's default is UTF-16 units."""
    target = tmp_path / "sample.py"
    target.write_text(_NON_ASCII, encoding="utf-8")
    monkeypatch.chdir(tmp_path)

    _code, json_out, _err = _run_cli(
        ["check", "sample.py", "--format", "json"], capsys)
    byte_col = json.loads(json_out)[0]["col_offset"]
    line = target.read_text(encoding="utf-8").splitlines()[1]
    expected = (len(line.encode("utf-8")[:byte_col].decode("utf-8")
                    .encode("utf-16-le")) // 2) + 1

    data = _sarif(capsys, ["check", "sample.py", "--format", "sarif"])
    region = data["runs"][0]["results"][0]["locations"][0][
        "physicalLocation"]["region"]

    assert region["startColumn"] == expected, region
    assert region["startColumn"] != byte_col + 1, "columns were not converted"


def test_sarif_reports_the_end_of_the_finding(tmp_path, monkeypatch,
                                               capsys) -> None:
    _write(tmp_path, monkeypatch)
    data = _sarif(capsys, ["check", "sample.py", "--format", "sarif"])
    region = data["runs"][0]["results"][0]["locations"][0][
        "physicalLocation"]["region"]

    assert region["endLine"] >= region["startLine"]
    assert (region["endLine"], region["endColumn"]) > (
        region["startLine"], region["startColumn"])


def test_diagnostics_keep_end_positions(tmp_path, monkeypatch) -> None:
    from pcdlint.analyzer import analyze_code

    _write(tmp_path, monkeypatch)
    source = (tmp_path / "sample.py").read_text(encoding="utf-8")
    found = analyze_code(source, "sample.py")
    assert found, "control: expected at least one finding"
    for d in found:
        assert d.end_lineno is not None, d
        assert d.end_col_offset is not None, d
        assert (d.end_lineno, d.end_col_offset) >= (d.lineno, d.col_offset)


def test_sarif_declares_a_default_level_per_rule(tmp_path, monkeypatch,
                                                 capsys) -> None:
    """A consumer filters on defaultConfiguration before any result exists."""
    _write(tmp_path, monkeypatch)
    data = _sarif(capsys, ["check", "sample.py", "--format", "sarif"])

    rules = data["runs"][0]["tool"]["driver"]["rules"]
    defaults = {r["id"]: r["defaultConfiguration"]["level"] for r in rules}
    assert set(defaults) == {"PCL001", "PCL002", "PCL003", "PCL004", "PCL005"}
    assert all(level in ("error", "warning") for level in defaults.values())

    for result in data["runs"][0]["results"]:
        assert result["level"] == defaults[result["ruleId"]], result
