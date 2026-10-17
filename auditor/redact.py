"""Redaction at the scanner boundary.

Nothing downstream of this module needs a raw token value.  Replacing the
longest values first means a token that is a prefix of another cannot leave a
partial value behind in evidence.
"""

from __future__ import annotations

import re
from typing import Iterable

from .models import Token


def redact_text(text: str, tokens: Iterable[Token]) -> str:
    """Replace every inventory token value in *text* with its token_id marker."""
    ordered = sorted(
        (token for token in tokens if token.value),
        key=lambda token: (-len(token.value), token.token_id),
    )
    if not ordered:
        return text

    marker_by_value = {
        token.value: f"[REDACTED:{token.token_id}]" for token in ordered
    }
    pattern = re.compile("|".join(re.escape(token.value) for token in ordered))
    return pattern.sub(lambda match: marker_by_value[match.group(0)], text)
