"""Immutable data model shared by the loader, rules, scanner and report."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

# Inventory token states (authoritative classification).
ACTIVE_IN_FIXTURE = "active_in_fixture"
REVOKED_IN_FIXTURE = "revoked_in_fixture"
TEST_ONLY = "test_only"
TOKEN_STATES = (ACTIVE_IN_FIXTURE, REVOKED_IN_FIXTURE, TEST_ONLY)

# Simplified CI schema values (not real provider syntax).
TRIGGERS = ("pull_request", "tag")
PERMISSIONS = ("read-only", "release-write", "write-all")

DECISION_FINDING = "finding"
DECISION_BENIGN = "benign"


@dataclass(frozen=True)
class Token:
    """One inventory token.

    ``value`` is excluded from ``repr`` so an accidental debug print cannot
    leak the DEMO marker.  The loader rejects empty values and newlines.
    """

    token_id: str
    value: str = field(repr=False)
    state: str


@dataclass(frozen=True)
class Workflow:
    """One simplified CI workflow definition."""

    workflow_id: str
    trigger: str
    runs_untrusted_code: bool
    secret_refs: tuple[str, ...]
    permissions: str
    log_environment: bool
    artifact_paths: tuple[str, ...]


@dataclass(frozen=True)
class Snapshot:
    """A loaded snapshot: metadata, CI configuration and its root directory."""

    root: Path
    name: str
    tokens: tuple[Token, ...]
    workflows: tuple[Workflow, ...]
    token_by_id: dict[str, Token] = field(repr=False)


@dataclass(frozen=True)
class Finding:
    """A single auditable decision.

    ``decision`` is ``finding`` for a policy risk and ``benign`` for an
    explicit, evidence-backed non-finding.  ``evidence`` is always redacted
    before it reaches this object.
    """

    rule_id: str
    decision: str
    severity: str
    evidence: str
    rationale: str
    next_action: str
    workflow_id: Optional[str] = None
    path: Optional[str] = None
    line: Optional[int] = None
    token_id: Optional[str] = None

    def to_dict(self) -> dict:
        return {
            "rule_id": self.rule_id,
            "decision": self.decision,
            "severity": self.severity,
            "workflow_id": self.workflow_id,
            "path": self.path,
            "line": self.line,
            "token_id": self.token_id,
            "evidence": self.evidence,
            "rationale": self.rationale,
            "next_action": self.next_action,
        }

    def sort_key(self) -> tuple:
        """Stable ordering independent of input file order."""
        return (
            self.rule_id,
            self.path or "",
            self.workflow_id or "",
            self.line or 0,
            self.token_id or "",
            self.decision,
        )
