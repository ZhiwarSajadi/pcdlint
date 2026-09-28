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


def test_pcl001_detects_concat_with_taint_first() -> None:
    """PCL001: f'Time: {now}\\n' + STATIC_RULES triggers PCL001."""
    source = '''
from datetime import datetime
from openai import OpenAI

STATIC_RULES = "Be helpful."
now = datetime.now()
system = f"Time: {now}\\n" + STATIC_RULES

client = OpenAI()
client.chat.completions.create(
    model="gpt-4",
    system=system,
)
'''
    diags = analyze_code(source, "test.py")
    pcl001 = [d for d in diags if d.rule_id == "PCL001"]
    assert len(pcl001) >= 1, f"Expected PCL001 error, got {diags}"


def test_pcl001_allows_concat_with_static_first() -> None:
    """PCL001: STATIC_RULES + f'\\nTime: {now}' must NOT trigger PCL001."""
    source = '''
from datetime import datetime
from openai import OpenAI

STATIC_RULES = "Be helpful."
now = datetime.now()
system = STATIC_RULES + f"\\nTime: {now}"

client = OpenAI()
client.chat.completions.create(
    model="gpt-4",
    system=system,
)
'''
    diags = analyze_code(source, "test.py")
    pcl001 = [d for d in diags if d.rule_id == "PCL001"]
    assert len(pcl001) == 0, f"Expected 0 PCL001 errors, got {diags}"


def test_pcl003_detects_fstring_set_interpolation() -> None:
    """PCL003: f'{tag_set}' without sorted() triggers PCL003."""
    source = '''
tag_set = {"tag1", "tag2"}
prompt = f"Tags: {tag_set}"
'''
    diags = analyze_code(source, "test.py")
    pcl003 = [d for d in diags if d.rule_id == "PCL003"]
    assert len(pcl003) >= 1, f"Expected PCL003 error, got {diags}"


def test_pcl004_detects_dynamic_mutation_in_if_branch() -> None:
    """PCL004: mutating tools inside if branch triggers PCL004."""
    source = '''
import anthropic

tools = [{"name": "tool1"}]
include_extra = True
if include_extra:
    tools.append({"name": "tool2"})

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
    import sys

    from pcdlint.cli import main

    old_argv = sys.argv
    try:
        sys.argv = ["pcdlint", "check", "demo_good.py"]
        exit_code = main()
        assert exit_code == 0
    finally:
        sys.argv = old_argv


def test_cli_exit_code_on_errors() -> None:
    """CLI must return exit code 1 when errors are present."""
    import sys

    from pcdlint.cli import main

    old_argv = sys.argv
    try:
        sys.argv = ["pcdlint", "check", "demo_buggy.py"]
        exit_code = main()
        assert exit_code == 1
    finally:
        sys.argv = old_argv


def test_pcl001_detects_method_call_on_taint_source() -> None:
    """PCL001: datetime.now().isoformat() or strftime() triggers PCL001."""
    source = '''
from datetime import datetime
from openai import OpenAI

STATIC_RULES = "Be helpful."
now = datetime.now().isoformat()
system = f"Time: {now}\\n" + STATIC_RULES

client = OpenAI()
client.chat.completions.create(model="gpt-4", system=system)
'''
    diags = analyze_code(source, "test.py")
    pcl001 = [d for d in diags if d.rule_id == "PCL001"]
    assert len(pcl001) >= 1, f"Expected PCL001 for now.isoformat(), got {diags}"


def test_pcl001_detects_str_cast_on_uuid() -> None:
    """PCL001: str(uuid.uuid4()) triggers PCL001 when placed at start."""
    source = '''
import uuid
from openai import OpenAI

STATIC_RULES = "Be helpful."
uid = str(uuid.uuid4())
system = f"User: {uid}\\n" + STATIC_RULES

client = OpenAI()
client.chat.completions.create(model="gpt-4", system=system)
'''
    diags = analyze_code(source, "test.py")
    pcl001 = [d for d in diags if d.rule_id == "PCL001"]
    assert len(pcl001) >= 1, f"Expected PCL001 for str(uuid.uuid4()), got {diags}"


def test_pcl001_detects_variable_alias_taint() -> None:
    """PCL001: Taint propagates through variable aliasing t2 = t1."""
    source = '''
from datetime import datetime
from openai import OpenAI

STATIC_RULES = "Be helpful."
t1 = datetime.now()
t2 = t1
system = f"Time: {t2}\\n" + STATIC_RULES

client = OpenAI()
client.chat.completions.create(model="gpt-4", system=system)
'''
    diags = analyze_code(source, "test.py")
    pcl001 = [d for d in diags if d.rule_id == "PCL001"]
    assert len(pcl001) >= 1, f"Expected PCL001 for alias t2 = t1, got {diags}"


def test_pcl001_detects_type_annotated_assignment() -> None:
    """PCL001: Type-annotated variables (AnnAssign) are tracked for taint."""
    source = '''
from datetime import datetime
from openai import OpenAI

STATIC_RULES: str = "Be helpful."
now: str = datetime.now().isoformat()
system: str = f"Time: {now}\\n" + STATIC_RULES

client = OpenAI()
client.chat.completions.create(model="gpt-4", system=system)
'''
    diags = analyze_code(source, "test.py")
    pcl001 = [d for d in diags if d.rule_id == "PCL001"]
    assert len(pcl001) >= 1, f"Expected PCL001 for AnnAssign, got {diags}"


def test_pcl001_detects_anthropic_system_block_list() -> None:
    """PCL001: Anthropic structured system prompt list of blocks is inspected."""
    source = '''
import anthropic
from datetime import datetime

STATIC_RULES = "Be helpful."
now = datetime.now()
client = anthropic.Anthropic()
client.messages.create(
    model="claude-3",
    system=[
        {"type": "text", "text": f"Time: {now}\\n" + STATIC_RULES}
    ],
    messages=[{"role": "user", "content": "hello"}],
)
'''
    diags = analyze_code(source, "test.py")
    pcl001 = [d for d in diags if d.rule_id == "PCL001"]
    assert len(pcl001) >= 1, f"Expected PCL001 in system list of blocks, got {diags}"


def test_pcl001_detects_messages_append_taint() -> None:
    """PCL001: Messages populated via messages.append(...) are tracked."""
    source = '''
from datetime import datetime
from openai import OpenAI

STATIC_RULES = "Be helpful."
now = datetime.now()
messages = []
messages.append({"role": "system", "content": f"Time: {now}\\n" + STATIC_RULES})

client = OpenAI()
client.chat.completions.create(model="gpt-4", messages=messages)
'''
    diags = analyze_code(source, "test.py")
    pcl001 = [d for d in diags if d.rule_id == "PCL001"]
    assert len(pcl001) >= 1, f"Expected PCL001 in appended message, got {diags}"


@pytest.mark.parametrize("call_expr", [
    "datetime.now()",
    "datetime.utcnow()",
    "date.today()",
    "time.time()",
    "time.monotonic()",
    "time.perf_counter()",
    "uuid.uuid4()",
    "uuid.uuid1()",
    "random.random()",
    "random.randint(1, 100)",
    "random.choice(['a', 'b'])",
    "random.randrange(10)",
    "secrets.token_hex(16)",
    "secrets.token_urlsafe(16)",
    "secrets.token_bytes(16)",
    "os.urandom(16)",
    "os.getpid()",
    "time.time_ns()",
    "random.choices(['a', 'b'], k=2)",
    "random.sample(['a', 'b'], k=2)",
])
def test_pcl001_recognizes_all_20_taint_sources(call_expr: str) -> None:
    """PCL001: Every registered taint source is detected at prefix position."""
    source = f'''
import datetime, time, uuid, random, secrets, os
from datetime import datetime, date
from openai import OpenAI

STATIC_RULES = "Static prefix rules here."
val = {call_expr}
system = f"Prefix: {{val}}\\n" + STATIC_RULES

client = OpenAI()
client.chat.completions.create(model="gpt-4", system=system)
'''
    diags = analyze_code(source, "test.py")
    pcl001 = [d for d in diags if d.rule_id == "PCL001"]
    assert len(pcl001) >= 1, f"Failed to detect taint source: {call_expr}, diags: {diags}"


def test_pcl002_allows_unrelated_json_dumps() -> None:
    """PCL002: json.dumps without sort_keys for file write does NOT trigger PCL002."""
    source = '''
import json

def save_cache(cache):
    with open("cache.json", "w") as f:
        f.write(json.dumps(cache))
'''
    diags = analyze_code(source, "test.py")
    pcl002 = [d for d in diags if d.rule_id == "PCL002"]
    assert len(pcl002) == 0, f"Expected 0 PCL002 on unrelated json.dumps, got {diags}"


def test_pcl002_detects_sort_keys_false() -> None:
    """PCL002: sort_keys=False explicitly set in prompt triggers PCL002."""
    source = '''
import json
from openai import OpenAI

data = {"b": 1, "a": 2}
prompt = json.dumps(data, sort_keys=False)

client = OpenAI()
client.chat.completions.create(
    model="gpt-4",
    messages=[{"role": "user", "content": prompt}],
)
'''
    diags = analyze_code(source, "test.py")
    pcl002 = [d for d in diags if d.rule_id == "PCL002"]
    assert len(pcl002) >= 1, f"Expected PCL002 for sort_keys=False, got {diags}"


def test_pcl003_detects_str_set() -> None:
    """PCL003: str(tag_set) without sorted() triggers PCL003."""
    source = '''
from openai import OpenAI

tag_set = {"tag1", "tag2"}
prompt = str(tag_set)

client = OpenAI()
client.chat.completions.create(
    model="gpt-4",
    messages=[{"role": "user", "content": prompt}],
)
'''
    diags = analyze_code(source, "test.py")
    pcl003 = [d for d in diags if d.rule_id == "PCL003"]
    assert len(pcl003) >= 1, f"Expected PCL003 for str(set), got {diags}"


def test_pcl003_allows_str_sorted_set() -> None:
    """PCL003: str(sorted(tag_set)) should NOT trigger PCL003."""
    source = '''
from openai import OpenAI

tag_set = {"tag1", "tag2"}
prompt = str(sorted(tag_set))

client = OpenAI()
client.chat.completions.create(
    model="gpt-4",
    messages=[{"role": "user", "content": prompt}],
)
'''
    diags = analyze_code(source, "test.py")
    pcl003 = [d for d in diags if d.rule_id == "PCL003"]
    assert len(pcl003) == 0, f"Expected no PCL003 for str(sorted(set)), got {diags}"


def test_pcl004_detects_tools_constructed_from_set() -> None:
    """PCL004: tools = list(tool_set) triggers PCL004."""
    source = '''
import anthropic

tool_set = {"tool1", "tool2"}
tools = list(tool_set)

client = anthropic.Anthropic()
client.messages.create(
    model="claude-3",
    messages=[{"role": "user", "content": "hello"}],
    tools=tools,
)
'''
    diags = analyze_code(source, "test.py")
    pcl004 = [d for d in diags if d.rule_id == "PCL004"]
    assert len(pcl004) >= 1, f"Expected PCL004 for tools from set, got {diags}"


def test_pcl004_allows_sorted_tools() -> None:
    """PCL004: tools = sorted(tool_set) is deterministic and does NOT trigger PCL004."""
    source = '''
import anthropic

tool_set = {"tool1", "tool2"}
tools = sorted(tool_set)

client = anthropic.Anthropic()
client.messages.create(
    model="claude-3",
    messages=[{"role": "user", "content": "hello"}],
    tools=tools,
)
'''
    diags = analyze_code(source, "test.py")
    pcl004 = [d for d in diags if d.rule_id == "PCL004"]
    assert len(pcl004) == 0, f"Expected 0 PCL004 for sorted(tools), got {diags}"


def test_cli_json_format_output(capsys: pytest.CaptureFixture) -> None:
    """CLI: --format json produces valid JSON with all diagnostic keys."""
    import json
    import sys

    from pcdlint.cli import main

    old_argv = sys.argv
    try:
        sys.argv = ["pcdlint", "check", "demo_buggy.py", "--format", "json"]
        main()
        captured = capsys.readouterr()
        data = json.loads(captured.out)
        assert isinstance(data, list)
        assert len(data) >= 4
        for item in data:
            assert "rule_id" in item
            assert "fix_suggestion" in item
            assert "severity" in item
    finally:
        sys.argv = old_argv


def test_cli_fail_on_warn_flag() -> None:
    """CLI: --fail-on-warn exits with 1 when warnings exist."""
    import sys

    from pcdlint.cli import main

    old_argv = sys.argv
    try:
        # demo_buggy has both errors and warnings
        sys.argv = ["pcdlint", "check", "demo_buggy.py", "--fail-on-warn"]
        exit_code = main()
        assert exit_code == 1
    finally:
        sys.argv = old_argv


def test_cli_version_flag() -> None:
    """CLI: --version outputs version string."""
    import sys

    from pcdlint.cli import main

    old_argv = sys.argv
    try:
        sys.argv = ["pcdlint", "--version"]
        with pytest.raises(SystemExit) as exc:
            main()
        assert exc.value.code == 0
    finally:
        sys.argv = old_argv


def test_analyzer_handles_syntax_error_gracefully() -> None:
    """Analyzer returns empty list for unparseable syntax without crashing."""
    diags = analyze_code("def broken_syntax(:", "broken.py")
    assert diags == []


def test_analyze_path_directory(tmp_path: pytest.TempPathFactory) -> None:
    """analyze_path recursively walks directories and skips ignored folders."""
    from pathlib import Path

    from pcdlint.analyzer import analyze_path

    # Create directory with valid and buggy python files
    test_dir = Path(tmp_path) / "test_project"
    test_dir.mkdir()
    (test_dir / "clean.py").write_text("x = 1\n", encoding="utf-8")

    # Ignored directory
    venv_dir = test_dir / ".venv"
    venv_dir.mkdir()
    (venv_dir / "ignored.py").write_text("import json\nprompt = json.dumps({})\n", encoding="utf-8")

    diags = analyze_path(test_dir)
    assert len(diags) == 0


def test_cli_no_args_prints_help(capsys: pytest.CaptureFixture) -> None:
    """CLI with no arguments displays help and returns 0."""
    import sys

    from pcdlint.cli import main

    old_argv = sys.argv
    try:
        sys.argv = ["pcdlint"]
        code = main()
        assert code == 0
    finally:
        sys.argv = old_argv


def test_tracker_properties_and_static_solids() -> None:
    """Test TaintTracker property accessors and file-read static prefix solid recognition."""
    import ast

    from pcdlint.taint import TaintTracker

    code = '''
SYSTEM_PROMPT = open("prompt.txt").read()
tag_set = {"a", "b"}
now = datetime.now()
'''
    tree = ast.parse(code)
    tracker = TaintTracker()
    for node in ast.walk(tree):
        if isinstance(node, (ast.Assign, ast.AnnAssign)):
            tracker.track_assignment(node)

    assert "SYSTEM_PROMPT" in tracker.static_prefix_vars
    assert "tag_set" in tracker.set_vars
    assert "now" in tracker.tainted_vars
    assert "now" in tracker.prefix_tainted_vars


def test_format_call_taint_ordering() -> None:
    """Test str.format ordering: static first is allowed, taint first triggers PCL001."""
    # Static first:
    clean_code = '''
from datetime import datetime
from openai import OpenAI

STATIC_RULES = "Be helpful."
now = datetime.now()
system = "{}\\nTime: {}".format(STATIC_RULES, now)
client = OpenAI()
client.chat.completions.create(model="gpt-4", system=system)
'''
    assert [d for d in analyze_code(clean_code) if d.rule_id == "PCL001"] == []

    # Taint first:
    buggy_code = '''
from datetime import datetime
from openai import OpenAI

STATIC_RULES = "Be helpful."
now = datetime.now()
system = "Time: {}\\n{}".format(now, STATIC_RULES)
client = OpenAI()
client.chat.completions.create(model="gpt-4", system=system)
'''
    assert len([d for d in analyze_code(buggy_code) if d.rule_id == "PCL001"]) >= 1


def test_pcdlint_main_module() -> None:
    """Invoking python -m pcdlint executes __main__.py successfully."""
    import subprocess
    import sys

    result = subprocess.run(
        [sys.executable, "-m", "pcdlint", "--version"],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0
    assert "pcdlint" in result.stdout


def test_binop_non_add_does_not_infinite_recurse() -> None:
    """Non-Add BinOps (such as bitwise OR or multiplication) must not trigger recursion errors."""
    code = '''
x = 1 | 2
y = 10 * 20
z = x & y
'''
    diags = analyze_code(code)
    assert diags == []


def test_main_module_guard_body_runs() -> None:
    """__main__.py's `if __name__ == "__main__"` body exits through main()."""
    import runpy
    import sys

    import pcdlint.__main__ as entry

    old_argv = sys.argv
    try:
        sys.argv = ["pcdlint"]
        with pytest.raises(SystemExit) as excinfo:
            runpy.run_path(entry.__file__, run_name="__main__")
    finally:
        sys.argv = old_argv
    assert excinfo.value.code == 0





