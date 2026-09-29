"""Data model structures for pcdlint diagnostics and taint tracking."""

from dataclasses import dataclass


@dataclass
class TaintOrigin:
    """Describes where a tainted variable originates from."""

    variable_name: str
    source_call: str
    lineno: int


@dataclass(frozen=True)
class FuncSummary:
    """Everything a function's ``return`` tells us about its result.

    Taint alone was not enough: a helper returning a set or an unsorted
    ``json.dumps`` hands those properties to its caller too, and each is a
    separate rule (PCL004 and PCL002 respectively).
    """

    origin: TaintOrigin | None = None
    is_set: bool = False
    json_flows: frozenset[int] = frozenset()
    # Which parameters the return expression reads, and the parameter list
    # they index into. A helper's result depends on what its caller passed,
    # and only the caller can say whether that was dynamic: `ts` has no
    # origin of its own until `build(datetime.now())` supplies one.
    arg_names: tuple[str, ...] = ()
    returns_params: frozenset[int] = frozenset()


@dataclass(frozen=True)
class TextEdit:
    """A byte-precise replacement spanning part of a source file.

    Lines are 1-based; columns are 0-based *byte* offsets within the line,
    matching what ``ast`` reports (``col_offset`` counts UTF-8 bytes, not
    characters), so a span before a non-ASCII character still splices cleanly.
    """

    start_line: int
    start_col: int
    end_line: int
    end_col: int
    replacement: str


@dataclass
class Diagnostic:
    """A single lint diagnostic result."""

    file_path: str
    lineno: int
    col_offset: int
    rule_id: str  # PCL001 to PCL004
    rule_name: str
    message: str
    fix_suggestion: str
    severity: str  # "ERROR" or "WARNING"
    # Concrete rewrites for rules whose fix is mechanical. Empty for rules
    # where only a human can decide what the right code looks like.
    edits: tuple[TextEdit, ...] = ()
    # Span the finding covers, so a consumer can underline it rather than
    # plant a caret at one column. None only where ast recorded no end.
    end_lineno: int | None = None
    end_col_offset: int | None = None
