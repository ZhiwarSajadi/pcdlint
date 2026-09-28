"""Parsing of ``# pcdlint: disable`` suppression comments.

Four scopes are supported:

===============================  =============================================
``... # pcdlint: disable``       that line, every rule
``... # pcdlint: disable=PCL1``  that line, the named rules only
``# pcdlint: disable``           whole file (comment alone on its line)
``# pcdlint: disable=PCL002``    whole file, the named rules only
===============================  =============================================

Comments are found with :mod:`tokenize`, never by scanning raw text, so the
marker appearing inside a string literal is data and does nothing. A marker
naming an unknown rule suppresses nothing: a typo must surface the finding
rather than hide it.
"""

import io
import tokenize

from pcdlint.rules import KNOWN_RULE_IDS

MARKER = "pcdlint: disable"
# Stands for "every rule"; kept as a token so rule sets stay plain frozensets.
ALL_RULES = "*"


def _rule_ids(spec: str) -> set[str]:
    """Normalise a comma-separated ``PCL001,PCL002`` list to known ids only."""
    ids = {part.strip().upper() for part in spec.split(",") if part.strip()}
    return ids & KNOWN_RULE_IDS


def _marker_rules(comment: str) -> frozenset[str] | None:
    """Rule set a comment asks for, or None when it is not a marker at all."""
    text = comment.strip()
    if text.startswith("#"):
        text = text[1:].strip()
    if not text.startswith(MARKER):
        return None
    rest = text[len(MARKER):].strip()
    if not rest:
        return frozenset({ALL_RULES})
    if not rest.startswith("="):
        return None
    return frozenset(_rule_ids(rest[1:])) or None


class DisableSet:
    """Suppression scopes parsed out of one file's comments."""

    __slots__ = ("file_rules", "line_rules")

    def __init__(self, file_rules: frozenset[str],
                 line_rules: dict[int, frozenset[str]]) -> None:
        self.file_rules = file_rules
        self.line_rules = line_rules

    @staticmethod
    def _hit(rules: frozenset[str] | None, rule_id: str) -> bool:
        if not rules:
            return False
        return ALL_RULES in rules or rule_id in rules

    def disabled(self, lineno: int, rule_id: str) -> bool:
        """True when ``rule_id`` on ``lineno`` was switched off by a comment."""
        return (self._hit(self.line_rules.get(lineno), rule_id)
                or self._hit(self.file_rules, rule_id))


def parse(source: str) -> DisableSet:
    """Extract every disable comment from ``source``."""
    # Fast path: the overwhelming majority of files contain no marker, and
    # tokenizing them would buy nothing.
    if MARKER not in source:
        return DisableSet(frozenset(), {})

    lines = source.splitlines()
    file_rules: set[str] = set()
    line_rules: dict[int, set[str]] = {}
    try:
        for tok in tokenize.generate_tokens(io.StringIO(source).readline):
            if tok.type != tokenize.COMMENT:
                continue
            rules = _marker_rules(tok.string)
            if rules is None:
                continue
            row, col = tok.start
            line = lines[row - 1] if 0 < row <= len(lines) else ""
            if line[:col].strip():
                # Trailing on real code: scoped to this line.
                line_rules.setdefault(row, set()).update(rules)
            else:
                # Alone on its line: scoped to the whole file.
                file_rules.update(rules)
    except (tokenize.TokenError, IndentationError, SyntaxError, ValueError):
        # ast.parse already succeeded, so this should be unreachable; a
        # suppression parse must never turn a good run into a traceback.
        return DisableSet(frozenset(), {})

    frozen = {row: frozenset(ids) for row, ids in line_rules.items()}
    return DisableSet(frozenset(file_rules), frozen)
