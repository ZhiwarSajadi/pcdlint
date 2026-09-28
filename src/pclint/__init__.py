"""pclint - Static Taint Linter for Prompt-Cache Determinism (package alias for pcdlint)."""

import warnings

from pcdlint import __version__
from pcdlint.analyzer import analyze_code, analyze_path
from pcdlint.cli import main
from pcdlint.models import Diagnostic, TaintOrigin
from pcdlint.rules import RuleEngine
from pcdlint.taint import TaintTracker

# The top-level name `pclint` can clash with any other distribution that
# ships one, so it goes away in 1.0. The `pclint` console script stays: it
# maps to pcdlint.cli:main and does not squat on an import name.
warnings.warn(
    "The 'pclint' package alias is deprecated and will be removed in 1.0; "
    "import 'pcdlint' instead. The 'pclint' console script keeps working.",
    DeprecationWarning,
    stacklevel=2,
)

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
