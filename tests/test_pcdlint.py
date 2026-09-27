"""Comprehensive unit tests for pcdlint."""

import pytest

from pcdlint.analyzer import analyze_code


def test_pcl001_detects_datetime_at_start_of_system_prompt() -> None:
    """PCL001: datetime.now() at start of system= triggers error."""
    source = '''
from datetime import datetime
from openai import OpenAI

now = datetime.now()
system = f"Time: {now}\\n{STATIC_RULES}"

client = OpenAI()
client.chat.completions.create(
    model="gpt-4",
    system=system,
)
'''
    diags = analyze_code(source, "test.py")
    pcl001 = [d for d in diags if d.rule_id == "PCL001"]
    assert len(pcl001) >= 1, f"Expected PCL001 error, got {diags}"


def test_pcl001_allows_datetime_at_end_of_system_prompt() -> None:
    """PCL001: datetime.now() at END of system prompt should NOT trigger."""
    source = '''
from datetime import datetime
from openai import OpenAI

STATIC_RULES = "Be helpful."
now = datetime.now()
system = f"{STATIC_RULES}\\nTime: {now}"

client = OpenAI()
client.chat.completions.create(
    model="gpt-4",
    system=system,
)
'''
    diags = analyze_code(source, "test.py")
    pcl001 = [d for d in diags if d.rule_id == "PCL001"]
    assert len(pcl001) == 0, f"Expected no PCL001 errors, got {diags}"


def test_pcl001_detects_uuid_in_openai_system_message() -> None:
    """PCL001: uuid.uuid4() in system message of OpenAI call triggers error."""
    source = '''
import uuid
from openai import OpenAI

uid = uuid.uuid4()
system = f"User: {uid}\\nRules: be helpful."

client = OpenAI()
client.chat.completions.create(
    model="gpt-4",
    system=system,
)
'''
    diags = analyze_code(source, "test.py")
    pcl001 = [d for d in diags if d.rule_id == "PCL001"]
    assert len(pcl001) >= 1, f"Expected PCL001 error, got {diags}"


def test_pcl002_detects_unsorted_json_dumps() -> None:
    """PCL002: json.dumps without sort_keys=True triggers warning."""
    source = '''
import json
from openai import OpenAI

data = {"b": 1, "a": 2}
prompt = json.dumps(data)

client = OpenAI()
client.chat.completions.create(
    model="gpt-4",
    messages=[{"role": "user", "content": prompt}],
)
'''
    diags = analyze_code(source, "test.py")
    pcl002 = [d for d in diags if d.rule_id == "PCL002"]
    assert len(pcl002) >= 1, f"Expected PCL002 warning, got {diags}"


def test_pcl002_allows_sorted_json_dumps() -> None:
    """PCL002: json.dumps with sort_keys=True should NOT trigger."""
    source = '''
import json
from openai import OpenAI

data = {"b": 1, "a": 2}
prompt = json.dumps(data, sort_keys=True)

client = OpenAI()
client.chat.completions.create(
    model="gpt-4",
    messages=[{"role": "user", "content": prompt}],
)
'''
    diags = analyze_code(source, "test.py")
    pcl002 = [d for d in diags if d.rule_id == "PCL002"]
    assert len(pcl002) == 0, f"Expected no PCL002 warnings, got {diags}"


def test_pcl003_detects_unsorted_set_in_prompt() -> None:
    """PCL003: set variable in string join without sorted() triggers error."""
    source = '''
from openai import OpenAI

tag_set = {"tag1", "tag2", "tag3"}
prompt = ", ".join(tag_set)

client = OpenAI()
client.chat.completions.create(
    model="gpt-4",
    messages=[{"role": "user", "content": prompt}],
)
'''
    diags = analyze_code(source, "test.py")
    pcl003 = [d for d in diags if d.rule_id == "PCL003"]
    assert len(pcl003) >= 1, f"Expected PCL003 error, got {diags}"


def test_pcl003_allows_sorted_set_in_prompt() -> None:
    """PCL003: set variable wrapped in sorted() should NOT trigger."""
    source = '''
from openai import OpenAI

tag_set = {"tag1", "tag2", "tag3"}
prompt = ", ".join(sorted(tag_set))

client = OpenAI()
client.chat.completions.create(
    model="gpt-4",
    messages=[{"role": "user", "content": prompt}],
)
'''
    diags = analyze_code(source, "test.py")
    pcl003 = [d for d in diags if d.rule_id == "PCL003"]
    assert len(pcl003) == 0, f"Expected no PCL003 errors, got {diags}"


def test_pcl004_detects_shuffled_tools_list() -> None:
    """PCL004: random.shuffle(tools) before messages.create triggers warning."""
    source = '''
import random
import anthropic

tools = [{"name": "tool1"}, {"name": "tool2"}]
random.shuffle(tools)

client = anthropic.Anthropic()
client.messages.create(
    model="claude-3",
    messages=[{"role": "user", "content": "hello"}],
    tools=tools,
)
'''
    diags = analyze_code(source, "test.py")
    pcl004 = [d for d in diags if d.rule_id == "PCL004"]
    assert len(pcl004) >= 1, f"Expected PCL004 warning, got {diags}"


def test_demo_good_file_passes_clean() -> None:
    """The clean demo_good.py must produce 0 errors or warnings."""
    from pathlib import Path
    from pcdlint.analyzer import analyze_path

    good_path = Path("demo_good.py")
    if good_path.exists():
        diags = analyze_path(good_path)
        assert len(diags) == 0, f"Expected 0 diagnostics on demo_good.py, got: {diags}"


def test_demo_buggy_file_triggers_all_rules() -> None:
    """The buggy demo_buggy.py must trigger all 4 rules: PCL001, PCL002, PCL003, PCL004."""
    from pathlib import Path
    from pcdlint.analyzer import analyze_path

    buggy_path = Path("demo_buggy.py")
    if buggy_path.exists():
        diags = analyze_path(buggy_path)
        rule_ids = {d.rule_id for d in diags}
        assert "PCL001" in rule_ids, "Missing PCL001"
        assert "PCL002" in rule_ids, "Missing PCL002"
        assert "PCL003" in rule_ids, "Missing PCL003"
        assert "PCL004" in rule_ids, "Missing PCL004"


def test_cli_check_command() -> None:
    """CLI should support `check` subcommand transparently."""
    from pcdlint.cli import main
    import sys

    old_argv = sys.argv
    try:
        sys.argv = ["pcdlint", "check", "demo_good.py"]
        exit_code = main()
        assert exit_code == 0
    finally:
        sys.argv = old_argv


def test_cli_exit_code_on_errors() -> None:
    """CLI must return exit code 1 when errors are present."""
    from pcdlint.cli import main
    import sys

    old_argv = sys.argv
    try:
        sys.argv = ["pcdlint", "check", "demo_buggy.py"]
        exit_code = main()
        assert exit_code == 1
    finally:
        sys.argv = old_argv

