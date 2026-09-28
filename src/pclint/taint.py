"""Static taint and prefix tracking engine for pclint (alias to pcdlint.taint)."""

from pcdlint.taint import (
    STATIC_PREFIX_NAMES,
    TAINT_SOURCES,
    TaintTracker,
)

__all__ = [
    "STATIC_PREFIX_NAMES",
    "TAINT_SOURCES",
    "TaintTracker",
]
