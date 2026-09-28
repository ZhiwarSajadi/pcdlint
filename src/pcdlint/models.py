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
