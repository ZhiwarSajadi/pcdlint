"""Static taint and prefix tracking engine for pclint (alias to pcdlint.taint)."""

from pcdlint.taint import (
    TAINT_SOURCES,
    STATIC_PREFIX_NAMES,
    TaintTracker,
)

__all__ = [
    "TAINT_SOURCES",
    "STATIC_PREFIX_NAMES",
    "TaintTracker",
]
