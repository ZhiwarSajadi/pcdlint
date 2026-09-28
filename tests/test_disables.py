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
    """The keyword only counts as a marker, not as a word inside prose."""
    marked = BASE.replace(
        "    system=system,\n",
        "    system=system,  # see pcdlint: disable for the syntax\n",
    )
    assert len(analyze_code(marked, "t.py")) >= 1


# --- the marker no longer has to start the comment ------------------------

def test_marker_after_another_pragma_on_the_same_comment_suppresses() -> None:
    """`# type: ignore  # pcdlint: disable` is a single comment token."""
    marked = BASE.replace(
        "    system=system,\n",
        "    system=system,  # type: ignore  # pcdlint: disable\n",
    )
    assert analyze_code(marked, "t.py") == []


def test_marker_after_a_noqa_on_the_same_comment_suppresses() -> None:
    """`# noqa: E501 pcdlint: disable` shares one token with the noqa."""
    marked = BASE.replace(
        "    system=system,\n",
        "    system=system,  # noqa: E501 pcdlint: disable\n",
    )
    assert analyze_code(marked, "t.py") == []


def test_marker_without_spaces_suppresses() -> None:
    """`#pcdlint:disable` is the same marker with no padding."""
    marked = BASE.replace(
        "    system=system,\n",
        "    system=system,  #pcdlint:disable\n",
    )
    assert analyze_code(marked, "t.py") == []


def test_marker_followed_by_extra_word_is_not_a_marker() -> None:
    """`disable-all` extends the keyword, so the word is not the marker."""
    marked = BASE.replace(
        "    system=system,\n",
        "    system=system,  # pcdlint:disable-all\n",
    )
    assert len(analyze_code(marked, "t.py")) >= 1


# --- a standalone marker below the header scopes to the next line ---------

def test_standalone_marker_mid_file_is_not_file_scoped() -> None:
    """A marker below the first statement used to switch off the whole file.

    Anyone coming from eslint or pylint writes `# pcdlint: disable` on the
    line above the code they mean; it silently silenced every finding in
    the file instead.
    """
    source = BASE.replace(
        "client = OpenAI()\n",
        "client = OpenAI()\n# pcdlint: disable\n",
    )
    assert source != BASE, "the marker line was not inserted"

    pcl001 = [d for d in analyze_code(source, "t.py") if d.rule_id == "PCL001"]
    assert len(pcl001) == 1, (
        "a mid-file standalone marker must not silence the rest of the file, "
        f"got {pcl001}"
    )


def test_standalone_marker_directly_above_a_line_suppresses_that_line() -> None:
    """The next line after a standalone marker is the one it means."""
    source = BASE.replace(
        "    system=system,\n",
        "    # pcdlint: disable\n    system=system,\n",
    )
    assert source != BASE, "the marker line was not inserted"
    assert analyze_code(source, "t.py") == []


def test_standalone_marker_at_end_of_file_suppresses_nothing() -> None:
    """There is no next line, so the marker has nothing to switch off."""
    source = BASE + "# pcdlint: disable\n"
    pcl001 = [d for d in analyze_code(source, "t.py") if d.rule_id == "PCL001"]
    assert len(pcl001) == 1, f"a trailing marker must be inert, got {pcl001}"
