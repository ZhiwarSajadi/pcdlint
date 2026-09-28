"""Tests for `# pcdlint: disable` comments."""

from pcdlint.analyzer import analyze_code

# Diagnostic lands on the `system=system,` argument line (line 11).
BASE = '''
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

MARKED = BASE.replace("    system=system,\n", "    system=system,  # pcdlint: disable\n")


def test_bare_marker_suppresses_finding_on_its_line() -> None:
    """A trailing `# pcdlint: disable` silences the diagnostic reported on that line."""
    assert analyze_code(BASE), "control: unmarked source must produce diagnostics"
    assert analyze_code(MARKED, "t.py") == []


def test_marker_on_a_different_line_does_not_suppress() -> None:
    """The marker only applies to the line it sits on, not the whole call."""
    shifted = BASE.replace(
        'system = f"Time: {now}\\n{STATIC_RULES}"',
        'system = f"Time: {now}\\n{STATIC_RULES}"  # pcdlint: disable',
    )
    assert shifted != BASE
    pcl001 = [d for d in analyze_code(shifted, "t.py") if d.rule_id == "PCL001"]
    assert len(pcl001) == 1, f"marker on line 6 must not suppress line 11, got {pcl001}"


def test_named_marker_suppresses_only_that_rule() -> None:
    """`# pcdlint: disable=PCL001` silences PCL001 on that line."""
    marked = BASE.replace(
        "    system=system,\n", "    system=system,  # pcdlint: disable=PCL001\n"
    )
    assert analyze_code(marked, "t.py") == []


def test_named_marker_for_other_rule_leaves_finding() -> None:
    """Naming a different rule must not silence PCL001."""
    marked = BASE.replace(
        "    system=system,\n", "    system=system,  # pcdlint: disable=PCL002\n"
    )
    pcl001 = [d for d in analyze_code(marked, "t.py") if d.rule_id == "PCL001"]
    assert len(pcl001) == 1, f"PCL002 marker must not silence PCL001, got {pcl001}"


def test_marker_inside_string_literal_is_ignored() -> None:
    """A marker appearing as data in a string is not a comment and does nothing."""
    source = 'NOTE = "# pcdlint: disable"\n' + BASE
    assert len(analyze_code(source, "t.py")) >= 1


def test_malformed_marker_is_ignored() -> None:
    """An unknown rule id silences nothing rather than guessing."""
    marked = BASE.replace(
        "    system=system,\n", "    system=system,  # pcdlint: disable=NOTARULE\n"
    )
    assert len(analyze_code(marked, "t.py")) >= 1


def test_file_level_marker_suppresses_every_finding() -> None:
    """`# pcdlint: disable` alone on its own line disables the whole file."""
    source = "# pcdlint: disable\n" + BASE
    assert analyze_code(source, "t.py") == []


def test_file_level_marker_named_suppresses_only_named_rule() -> None:
    """A standalone `# pcdlint: disable=PCL002` leaves other rules active."""
    source = "# pcdlint: disable=PCL002\n" + BASE
    pcl001 = [d for d in analyze_code(source, "t.py") if d.rule_id == "PCL001"]
    assert len(pcl001) == 1, f"file-level PCL002 disable must not silence PCL001, got {pcl001}"


def test_file_level_marker_ignores_string_literals() -> None:
    """File-level detection uses real comments, not any line containing the text."""
    source = 'x = "# pcdlint: disable"\n' + BASE
    assert len(analyze_code(source, "t.py")) >= 1


def test_multiple_named_rules_are_accepted() -> None:
    """`disable=PCL001,PCL003` is a valid comma-separated list."""
    marked = BASE.replace(
        "    system=system,\n",
        "    system=system,  # pcdlint: disable=PCL001,PCL003\n",
    )
    assert analyze_code(marked, "t.py") == []


def test_marker_prefix_that_is_not_the_keyword_is_ignored() -> None:
    """`# pcdlint: disable-all` extends the keyword and is not a marker."""
    marked = BASE.replace(
        "    system=system,\n", "    system=system,  # pcdlint: disable-all\n"
    )
    assert len(analyze_code(marked, "t.py")) >= 1


def test_marker_text_mid_comment_is_not_a_marker() -> None:
    """The keyword only counts at the start of the comment, not inside prose."""
    marked = BASE.replace(
        "    system=system,\n",
        "    system=system,  # see pcdlint: disable for the syntax\n",
    )
    assert len(analyze_code(marked, "t.py")) >= 1
