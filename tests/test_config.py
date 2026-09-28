"""Tests for [tool.pcdlint] config discovery and --select / --ignore."""

import json
import sys

import pytest

from pcdlint.cli import main

# Fires PCL001 (ERROR), PCL002 (WARNING) and PCL003 (ERROR).
CODE = '''
import json
from datetime import datetime
from openai import OpenAI

now = datetime.now()
tags = {"a", "b"}
data = {"b": 1, "a": 2}
system = f"Time: {now} " + json.dumps(data) + ", ".join(tags)

client = OpenAI()
client.chat.completions.create(model="gpt-4", system=system)
'''


def _write_project(tmp_path, config: str | None, code: str = CODE):
    if config is not None:
        (tmp_path / "pyproject.toml").write_text(config, encoding="utf-8")
    target = tmp_path / "app.py"
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(code, encoding="utf-8")
    return target


def _rule_ids(capsys, tmp_path, *args) -> set[str]:
    """Run the CLI over tmp_path and return the rule ids it reported."""
    old_argv = sys.argv
    try:
        sys.argv = ["pcdlint", "check", str(tmp_path), "--format", "json", *args]
        main()
    finally:
        sys.argv = old_argv
    out = capsys.readouterr().out
    return {d["rule_id"] for d in json.loads(out)}


def test_without_config_every_rule_runs(capsys, tmp_path) -> None:
    """No [tool.pcdlint] means all rules are active."""
    _write_project(tmp_path, None)
    assert _rule_ids(capsys, tmp_path) == {"PCL001", "PCL002", "PCL003"}


def test_select_limits_output_to_named_rules(capsys, tmp_path) -> None:
    """select = [...] is an allowlist."""
    _write_project(tmp_path, '[tool.pcdlint]\nselect = ["PCL002"]\n')
    assert _rule_ids(capsys, tmp_path) == {"PCL002"}


def test_ignore_drops_named_rule(capsys, tmp_path) -> None:
    """ignore = [...] removes rules from the run."""
    _write_project(tmp_path, '[tool.pcdlint]\nignore = ["PCL003"]\n')
    assert _rule_ids(capsys, tmp_path) == {"PCL001", "PCL002"}


def test_ignore_is_applied_after_select(capsys, tmp_path) -> None:
    """A rule in both select and ignore stays off."""
    _write_project(
        tmp_path, '[tool.pcdlint]\nselect = ["PCL001", "PCL003"]\nignore = ["PCL003"]\n'
    )
    assert _rule_ids(capsys, tmp_path) == {"PCL001"}


def test_config_is_found_walking_up_from_the_file(capsys, tmp_path) -> None:
    """A pyproject.toml above a nested package still applies to it."""
    _write_project(tmp_path, '[tool.pcdlint]\nselect = ["PCL002"]\n')
    nested = tmp_path / "pkg" / "deep"
    nested.mkdir(parents=True)
    (nested / "app.py").write_text(CODE, encoding="utf-8")
    assert _rule_ids(capsys, tmp_path / "pkg" / "deep") == {"PCL002"}


def test_unknown_config_key_exits_2(tmp_path, capsys) -> None:
    """A typo'd key must fail loudly rather than be silently ignored."""
    _write_project(tmp_path, '[tool.pcdlint]\nselct = ["PCL001"]\n')
    old_argv = sys.argv
    try:
        sys.argv = ["pcdlint", "check", str(tmp_path)]
        assert main() == 2
    finally:
        sys.argv = old_argv
    assert "selct" in capsys.readouterr().err


def test_unknown_rule_id_in_config_exits_2(tmp_path, capsys) -> None:
    """select = ["PCL999"] must not silently produce a clean run."""
    _write_project(tmp_path, '[tool.pcdlint]\nselect = ["PCL999"]\n')
    old_argv = sys.argv
    try:
        sys.argv = ["pcdlint", "check", str(tmp_path)]
        assert main() == 2
    finally:
        sys.argv = old_argv
    assert "PCL999" in capsys.readouterr().err


def test_invalid_toml_exits_2(tmp_path, capsys) -> None:
    """An unparseable pyproject.toml is an error, never a clean run."""
    _write_project(tmp_path, '[tool.pcdlint\nselect = broken\n')
    old_argv = sys.argv
    try:
        sys.argv = ["pcdlint", "check", str(tmp_path)]
        assert main() == 2
    finally:
        sys.argv = old_argv
    assert capsys.readouterr().err


def test_cli_select_overrides_config(capsys, tmp_path) -> None:
    """--select replaces the config's select rather than merging with it."""
    _write_project(tmp_path, '[tool.pcdlint]\nselect = ["PCL001"]\n')
    assert _rule_ids(capsys, tmp_path, "--select", "PCL002") == {"PCL002"}


def test_cli_ignore_overrides_config(capsys, tmp_path) -> None:
    """--ignore replaces the config's ignore rather than merging with it."""
    _write_project(tmp_path, '[tool.pcdlint]\nignore = ["PCL003"]\n')
    assert _rule_ids(capsys, tmp_path, "--ignore", "PCL002") == {"PCL001", "PCL003"}


def test_cli_select_rejects_unknown_rule(tmp_path, capsys) -> None:
    """A typo on the command line fails the same way a config typo does."""
    _write_project(tmp_path, None)
    old_argv = sys.argv
    try:
        sys.argv = ["pcdlint", "check", str(tmp_path), "--select", "PCL999"]
        assert main() == 2
    finally:
        sys.argv = old_argv
    assert "PCL999" in capsys.readouterr().err


def test_select_accepts_repeated_flag(capsys, tmp_path) -> None:
    """--select PCL001 --select PCL003 accumulates instead of replacing."""
    _write_project(tmp_path, None)
    assert _rule_ids(capsys, tmp_path, "--select", "PCL001", "--select", "PCL003") == {
        "PCL001",
        "PCL003",
    }


# --- an empty allowlist is an error, not a clean run ---------------------

def _exit_code(tmp_path, capsys, *args: str) -> tuple[int, str]:
    old_argv = sys.argv
    try:
        sys.argv = ["pcdlint", "check", str(tmp_path), *args]
        code = main()
    finally:
        sys.argv = old_argv
    return code, capsys.readouterr().err


def test_empty_select_in_config_exits_2(tmp_path, capsys) -> None:
    """select = [] switches every rule off, which reads as a clean run."""
    _write_project(tmp_path, '[tool.pcdlint]\nselect = []\n')

    code, err = _exit_code(tmp_path, capsys)

    assert code == 2, err
    assert "select" in err


def test_empty_ignore_in_config_is_allowed(capsys, tmp_path) -> None:
    """ignore = [] means "ignore nothing"; every rule must still run."""
    _write_project(tmp_path, '[tool.pcdlint]\nignore = []\n')
    assert _rule_ids(capsys, tmp_path) == {"PCL001", "PCL002", "PCL003"}


@pytest.mark.parametrize("flag_value", [",", "", " , , "])
def test_empty_cli_select_exits_2(tmp_path, capsys, flag_value: str) -> None:
    """--select "," is an empty allowlist, not "run everything"."""
    _write_project(tmp_path, None)

    code, err = _exit_code(tmp_path, capsys, "--select", flag_value)

    assert code == 2, err
    assert "--select" in err


def test_empty_cli_ignore_is_allowed(tmp_path, capsys) -> None:
    """--ignore "," selects nothing to ignore; the run must stay clean of errors."""
    _write_project(tmp_path, None)

    code, _err = _exit_code(tmp_path, capsys, "--ignore", ",")

    assert code == 1, "no rules should have been switched off"


# --- P3-2: config is looked up once per directory, not once per file ------

def test_config_is_parsed_once_per_directory(tmp_path, monkeypatch, capsys) -> None:
    """Every file in a directory re-walked the tree and re-parsed the same
    pyproject.toml."""
    from pcdlint import config as config_mod

    (tmp_path / "pyproject.toml").write_text(
        '[tool.pcdlint]\nselect = ["PCL002"]\n', encoding="utf-8")
    for name in ("a.py", "b.py", "c.py"):
        (tmp_path / name).write_text(CODE, encoding="utf-8")

    parsed = []
    original = config_mod._load
    monkeypatch.setattr(config_mod, "_load",
                        lambda path: (parsed.append(path), original(path))[1])

    _rule_ids(capsys, tmp_path)

    assert len(parsed) == 1, f"parsed the config {len(parsed)} times"


def test_a_broken_config_still_fails_every_call(tmp_path) -> None:
    """Caching must never turn a later failure into a silent clean run."""
    from pcdlint import config as config_mod

    (tmp_path / "pyproject.toml").write_text(
        "[tool.pcdlint\nselect = broken\n", encoding="utf-8")
    target = str(tmp_path / "a.py")

    with pytest.raises(config_mod.ConfigError):
        config_mod.load_for(target)
    with pytest.raises(config_mod.ConfigError):
        config_mod.load_for(target)
