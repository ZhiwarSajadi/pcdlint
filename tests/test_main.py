"""``python -m pcdlint`` reaches the CLI and returns its exit code."""

import runpy
import sys

import pytest

import pcdlint.__main__ as entry

BUGGY = (
    "from datetime import datetime\n"
    "system = f'{datetime.now()} ' + 'STATIC RULES ' * 30\n"
    "client.messages.create(model='m', system=system, messages=[])\n"
)


def _run(argv: list) -> int | None:
    """Execute ``__main__`` as a script and capture what it exits with."""
    old_argv = sys.argv
    try:
        sys.argv = argv
        with pytest.raises(SystemExit) as excinfo:
            runpy.run_path(entry.__file__, run_name="__main__")
    finally:
        sys.argv = old_argv
    return excinfo.value.code


def test_main_module_prints_help_and_exits_zero(capsys) -> None:
    assert _run(["pcdlint"]) == 0
    assert "usage:" in capsys.readouterr().out


def test_main_module_exits_one_when_findings_exist(tmp_path, monkeypatch,
                                                   capsys) -> None:
    target = tmp_path / "sample.py"
    target.write_text(BUGGY, encoding="utf-8")
    monkeypatch.chdir(tmp_path)

    assert _run(["pcdlint", "check", "sample.py"]) == 1
    assert "PCL001" in capsys.readouterr().out


def test_a_real_path_named_check_is_not_swallowed_as_a_subcommand(
        tmp_path, monkeypatch, capsys) -> None:
    """``check`` is only a subcommand when nothing on disk is called that.

    Otherwise the token was stripped, the default path ``.`` was substituted,
    and ``pcdlint check`` silently linted a different tree than the one the
    argument named.
    """
    (tmp_path / "check").mkdir()
    (tmp_path / "check" / "sample.py").write_text(BUGGY, encoding="utf-8")
    # Present so linting "." instead of "check" is visibly a different run.
    (tmp_path / "broken.py").write_text("def (:\n", encoding="utf-8")
    monkeypatch.chdir(tmp_path)

    code = _run(["pcdlint", "check"])
    captured = capsys.readouterr()

    assert code == 1, (captured.out, captured.err)
    assert "PCL001" in captured.out
    assert "broken.py" not in captured.err


def test_check_with_no_paths_lints_the_working_directory(tmp_path, monkeypatch,
                                                        capsys) -> None:
    """Guard: with no ``check`` path on disk, the default stays ``.``."""
    (tmp_path / "sample.py").write_text(BUGGY, encoding="utf-8")
    monkeypatch.chdir(tmp_path)

    assert _run(["pcdlint", "check"]) == 1
    assert "PCL001" in capsys.readouterr().out
