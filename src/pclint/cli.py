"""CLI entry point for pclint (alias to pcdlint.cli)."""

from pcdlint.cli import main

__all__ = ["main"]

if __name__ == "__main__":
    import sys
    sys.exit(main())
