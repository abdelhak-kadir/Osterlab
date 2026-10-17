"""S1: plaintext token scanning of the four supplied content directories."""

from __future__ import annotations

import os
from pathlib import Path

from .models import (
    ACTIVE_IN_FIXTURE,
    DECISION_BENIGN,
    DECISION_FINDING,
    TEST_ONLY,
    Finding,
    Snapshot,
    Token,
)
from .policy import SCANNED_DIRS
from .redact import redact_text


def list_content_files(root: Path) -> list[str]:
    """Return sorted POSIX-relative paths of supplied content files.

    Only ``app/``, ``tests/``, ``docs/`` and ``build/`` are walked.  Symlinks
    are skipped so the audit cannot escape the supplied snapshot.
    """
    files: list[str] = []
    for dirname in SCANNED_DIRS:
        base = root / dirname
        if base.is_symlink() or not base.is_dir():
            continue
        for current, dirnames, filenames in os.walk(base, followlinks=False):
            # Keep walk order deterministic and never descend into symlinks.
            dirnames[:] = sorted(
                name
                for name in dirnames
                if not (Path(current) / name).is_symlink()
            )
            for name in sorted(filenames):
                path = Path(current) / name
                if path.is_symlink() or not path.is_file():
                    continue
                files.append(path.relative_to(root).as_posix())
    return sorted(files)


def _match_tokens(line: str, tokens: tuple[Token, ...]) -> list[Token]:
    """Find non-overlapping token values on one line, longest value first.

    Longest-first span marking prevents a token value that is a prefix of a
    longer value from producing a second, spurious decision.  Repeated
    occurrences of the same token on a line collapse to one decision.
    """
    spans: list[tuple[int, int, Token]] = []
    for token in sorted(tokens, key=lambda item: (-len(item.value), item.token_id)):
        if not token.value:
            continue
        start = 0
        while True:
            index = line.find(token.value, start)
            if index < 0:
                break
            end = index + len(token.value)
            overlaps = any(
                index < span_end and end > span_start
                for span_start, span_end, _ in spans
            )
            if not overlaps:
                spans.append((index, end, token))
            start = index + 1

    spans.sort(key=lambda span: (span[0], span[1], span[2].token_id))
    matched: list[Token] = []
    seen_ids: set[str] = set()
    for _, _, token in spans:
        if token.token_id not in seen_ids:
            seen_ids.add(token.token_id)
            matched.append(token)
    return matched


def _s1_decision(token: Token, path: str, line: int, evidence: str) -> Finding:
    if token.state == ACTIVE_IN_FIXTURE:
        return Finding(
            rule_id="S1",
            decision=DECISION_FINDING,
            severity="critical",
            path=path,
            line=line,
            token_id=token.token_id,
            evidence=evidence,
            rationale=(
                "The inventory classifies this token as active_in_fixture, so "
                "its plaintext value in scanned content is exposure. S1 applies "
                "regardless of the filename."
            ),
            next_action=(
                "Remove the plaintext value, load it from the CI secret store, "
                "and rotate the credential."
            ),
        )

    if token.state == TEST_ONLY:
        return Finding(
            rule_id="S1",
            decision=DECISION_BENIGN,
            severity="info",
            path=path,
            line=line,
            token_id=token.token_id,
            evidence=evidence,
            rationale=(
                "The inventory classifies this token as test_only. It is a "
                "nonfunctional fixture marker, not current credential exposure."
            ),
            next_action=(
                "No credential action; keep the fixture marker nonfunctional."
            ),
        )

    return Finding(
        rule_id="S1",
        decision=DECISION_BENIGN,
        severity="info",
        path=path,
        line=line,
        token_id=token.token_id,
        evidence=evidence,
        rationale=(
            "The inventory classifies this token as revoked_in_fixture. The "
            "remaining text is stale but is not current credential exposure."
        ),
        next_action=(
            "Remove the stale value during repository cleanup; policy does not "
            "require rotation for an already-revoked marker."
        ),
    )


def scan_text(snapshot: Snapshot) -> list[Finding]:
    """Return S1 risk findings and explicit benign decisions.

    Files are read as UTF-8 with replacement, so a non-text file cannot crash
    the audit.  Evidence is redacted before it leaves this function.
    """
    decisions: list[Finding] = []
    for relative_path in list_content_files(snapshot.root):
        text = (snapshot.root / relative_path).read_text(
            encoding="utf-8", errors="replace"
        )
        for line_number, line in enumerate(text.splitlines(), start=1):
            for token in _match_tokens(line, snapshot.tokens):
                decisions.append(
                    _s1_decision(
                        token=token,
                        path=relative_path,
                        line=line_number,
                        evidence=redact_text(line, snapshot.tokens).strip(),
                    )
                )
    return decisions
