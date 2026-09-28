"""pclint - Static Taint Linter for Prompt-Cache Determinism (package alias for pcdlint)."""

from pcdlint import __version__
from pcdlint.analyzer import analyze_code, analyze_path
from pcdlint.cli import main
from pcdlint.models import Diagnostic, TaintOrigin
from pcdlint.rules import RuleEngine
from pcdlint.taint import TaintTracker

__all__ = [
    "Diagnostic",
    "RuleEngine",
    "TaintOrigin",
    "TaintTracker",
    "__version__",
    "analyze_code",
    "analyze_path",
    "main",
]
