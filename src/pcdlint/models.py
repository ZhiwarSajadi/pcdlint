"""Data model structures for pcdlint diagnostics and taint tracking."""

from dataclasses import dataclass, field


@dataclass
class TaintOrigin:
    """Describes where a tainted variable originates from."""

    variable_name: str
    source_call: str
    lineno: int


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
