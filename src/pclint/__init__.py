"""pclint - Static Taint Linter for Prompt-Cache Determinism (package alias for pcdlint)."""

from pcdlint import __version__
from pcdlint.models import Diagnostic, TaintOrigin
from pcdlint.taint import TaintTracker
from pcdlint.rules import RuleEngine
from pcdlint.analyzer import analyze_code, analyze_path
from pcdlint.cli import main

__all__ = [
    "__version__",
    "Diagnostic",
    "TaintOrigin",
    "TaintTracker",
    "RuleEngine",
    "analyze_code",
    "analyze_path",
    "main",
]
