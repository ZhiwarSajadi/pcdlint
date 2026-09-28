"""Mechanical rewrites for findings that have exactly one correct fix.

Columns arrive from ``ast`` as UTF-8 *byte* offsets, so every splice here
works on bytes: slicing the decoded string by column would cut a multi-byte
character in half.
"""

from collections.abc import Iterable

from pcdlint.models import TextEdit


def _line_byte_offsets(source: str) -> list[int]:
    """Byte offset of the first byte of each 1-based line."""
    offsets = [0]
    pos = 0
    while True:
        newline = source.find("\n", pos)
        if newline == -1:
            break
        offsets.append(offsets[-1] + len(source[pos:newline + 1].encode("utf-8")))
        pos = newline + 1
    return offsets


def apply_edits(source: str, edits: Iterable[TextEdit]) -> str:
    """Apply ``edits`` to ``source``, skipping any that overlap.

    Edits are applied highest-position-first so earlier writes cannot shift
    the offsets of later ones. An overlapping edit is dropped rather than
    merged: two rules fighting over one span means neither rewrite can be
    trusted, and a wrong splice would corrupt the file.
    """
    ordered = sorted(edits, key=lambda e: (e.start_line, e.start_col,
                                           e.end_line, e.end_col))
    accepted: list[TextEdit] = []
    for edit in ordered:
        if accepted and (edit.start_line, edit.start_col) \
                < (accepted[-1].end_line, accepted[-1].end_col):
            continue
        accepted.append(edit)
    if not accepted:
        return source

    offsets = _line_byte_offsets(source)
    data = bytearray(source.encode("utf-8"))
    for edit in reversed(accepted):
        if edit.start_line < 1 or edit.end_line > len(offsets):
            # An out-of-range span can only mean a rule computed it wrong;
            # refusing to splice beats writing a broken file.
            continue
        begin = offsets[edit.start_line - 1] + edit.start_col
        end = offsets[edit.end_line - 1] + edit.end_col
        data[begin:end] = edit.replacement.encode("utf-8")
    return data.decode("utf-8")
