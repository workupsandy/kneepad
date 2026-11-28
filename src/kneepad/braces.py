"""Bash brace expansion for the words the engine inspects.

Only what the shell would expand: ``{a,b}`` lists and ``{1..3}`` / ``{a..c}`` sequences,
nested and with a prefix or suffix. A brace group without a top-level comma or a valid
range stays literal, exactly as bash leaves it. The result is capped so a hostile
``{1..99999}{1..99999}`` cannot stall the hook; callers get ``None`` when the cap is hit.
"""

from __future__ import annotations

import re
from typing import List, Optional

MAX_EXPANSIONS = 512
_SEQ = re.compile(r"^(-?\d+)\.\.(-?\d+)(?:\.\.(-?\d+))?$")
_CSEQ = re.compile(r"^([A-Za-z])\.\.([A-Za-z])$")


def has_brace(text: str) -> bool:
    i = text.find("{")
    return i != -1 and text.find("}", i) != -1


def _split_top(body: str) -> List[str]:
    parts, depth, cur = [], 0, []
    for ch in body:
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
        if ch == "," and depth == 0:
            parts.append("".join(cur))
            cur = []
        else:
            cur.append(ch)
    parts.append("".join(cur))
    return parts


def _sequence(body: str) -> Optional[List[str]]:
    m = _SEQ.match(body)
    if m:
        a, b = int(m.group(1)), int(m.group(2))
        step = abs(int(m.group(3))) if m.group(3) else 1
        if step == 0:
            step = 1
        if abs(b - a) // step + 1 > MAX_EXPANSIONS:
            raise OverflowError(body)
        width = max(len(m.group(1)), len(m.group(2))) if (m.group(1).lstrip("-").startswith("0") or m.group(2).lstrip("-").startswith("0")) else 0
        rng = range(a, b + 1, step) if a <= b else range(a, b - 1, -step)
        return [str(n).zfill(width) for n in rng]
    m = _CSEQ.match(body)
    if m:
        a, b = ord(m.group(1)), ord(m.group(2))
        rng = range(a, b + 1) if a <= b else range(a, b - 1, -1)
        return [chr(c) for c in rng]
    return None


def _find_group(text: str, start: int = 0):
    """Return (open, close) of the first expandable top-level group at or after ``start``."""
    i = start
    n = len(text)
    while i < n:
        if text[i] == "{":
            depth, j = 0, i
            while j < n:
                if text[j] == "{":
                    depth += 1
                elif text[j] == "}":
                    depth -= 1
                    if depth == 0:
                        break
                j += 1
            if j < n:
                body = text[i + 1:j]
                if len(_split_top(body)) > 1 or _sequence(body) is not None:
                    return i, j
                # Literal group (``{}``, ``{x}``): bash keeps it, but a group nested inside may still expand.
                inner = _find_group(text, i + 1)
                if inner is not None and inner[1] < j:
                    return inner
                i = j + 1
                continue
        i += 1
    return None


def expand(text: str) -> Optional[List[str]]:
    """Expand ``text`` like bash. ``None`` means the expansion exceeded the cap."""
    try:
        return _expand(text)
    except OverflowError:
        return None


def _expand(text: str) -> Optional[List[str]]:
    out: List[str] = []
    stack = [text]
    while stack:
        cur = stack.pop()
        g = _find_group(cur)
        if g is None:
            out.append(cur)
            if len(out) > MAX_EXPANSIONS:
                return None
            continue
        o, c = g
        body = cur[o + 1:c]
        alts = _split_top(body)
        if len(alts) == 1:
            seq = _sequence(body)
            alts = seq if seq is not None else [body]
        pre, post = cur[:o], cur[c + 1:]
        for a in reversed(alts):
            stack.append(pre + a + post)
        if len(stack) + len(out) > MAX_EXPANSIONS * 2:
            return None
    return out
