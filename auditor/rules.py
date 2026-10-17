"""S2-S5 workflow rules, plus unresolved reference evidence.

Each rule is a pure decision over a loaded workflow and the resolved token
inventory.  CI references (token_id strings) are never confused with token
text matches from S1.
"""

from __future__ import annotations

import fnmatch
import json

from .models import (
    ACTIVE_IN_FIXTURE,
    DECISION_BENIGN,
    DECISION_FINDING,
    Finding,
    Snapshot,
    Workflow,
)
from .policy import SENSITIVE_PATHS
from .scanner import list_content_files

UNRESOLVED_RULE_ID = "CONFIG-UNRESOLVED"
WORKFLOW_BENIGN_RULE_ID = "WORKFLOW"


def _json_list(items) -> str:
    return json.dumps(list(items), ensure_ascii=True)


def _bool_text(value: bool) -> str:
    return "true" if value else "false"


def _dedupe(items) -> list[str]:
    seen: set[str] = set()
    ordered: list[str] = []
    for item in items:
        if item not in seen:
            seen.add(item)
            ordered.append(item)
    return ordered


def permissions_allowed(workflow: Workflow) -> bool:
    """S3 policy: read-only always; release-write only for a trusted tag."""
    if workflow.permissions == "read-only":
        return True
    return (
        workflow.permissions == "release-write"
        and workflow.trigger == "tag"
        and not workflow.runs_untrusted_code
    )


def _active_and_unknown(
    snapshot: Snapshot, workflow: Workflow
) -> tuple[list[str], list[str], list[str]]:
    refs = _dedupe(workflow.secret_refs)
    active = [
        ref
        for ref in refs
        if ref in snapshot.token_by_id
        and snapshot.token_by_id[ref].state == ACTIVE_IN_FIXTURE
    ]
    unknown = [ref for ref in refs if ref not in snapshot.token_by_id]
    return refs, active, unknown


def _s5_matches(
    workflow: Workflow, sensitive_present: list[str]
) -> list[tuple[str, str]]:
    """Return unique (pattern, matched_sensitive_path) pairs.

    ``fnmatchcase`` is used deliberately: it is case-sensitive on every
    platform, unlike ``fnmatch`` which normalizes case on Windows.  No glob or
    filesystem expansion is performed.
    """
    matches: list[tuple[str, str]] = []
    seen: set[tuple[str, str]] = set()
    for pattern in workflow.artifact_paths:
        for path in sensitive_present:
            pair = (pattern, path)
            if pair not in seen and fnmatch.fnmatchcase(path, pattern):
                seen.add(pair)
                matches.append(pair)
    return matches


def evaluate_workflows(snapshot: Snapshot) -> list[Finding]:
    """Evaluate S2-S5 for every workflow and emit benign evidence when clean."""
    supplied = set(list_content_files(snapshot.root))
    sensitive_present = [path for path in SENSITIVE_PATHS if path in supplied]
    decisions: list[Finding] = []

    for workflow in snapshot.workflows:
        refs, active_refs, unknown_refs = _active_and_unknown(snapshot, workflow)
        workflow_findings: list[Finding] = []

        # S2: untrusted code with an active secret reference.
        if workflow.runs_untrusted_code and active_refs:
            workflow_findings.append(
                Finding(
                    rule_id="S2",
                    decision=DECISION_FINDING,
                    severity="critical",
                    workflow_id=workflow.workflow_id,
                    evidence=(
                        f"trigger={workflow.trigger}; "
                        "runs_untrusted_code=true; "
                        f"active_secret_refs={_json_list(active_refs)}"
                    ),
                    rationale=(
                        "Untrusted code and an active secret reference coexist "
                        "in this workflow; the configuration permits secret "
                        "availability. The trigger alone does not prove "
                        "exploitation."
                    ),
                    next_action=(
                        "Remove active secret references from untrusted "
                        "workflows, or move the job to a trusted trigger; "
                        "rotate any credential that may have been exposed."
                    ),
                )
            )

        # S3: exact permission/trigger policy.
        if not permissions_allowed(workflow):
            workflow_findings.append(
                Finding(
                    rule_id="S3",
                    decision=DECISION_FINDING,
                    severity="high",
                    workflow_id=workflow.workflow_id,
                    evidence=(
                        f"trigger={workflow.trigger}; "
                        f"runs_untrusted_code="
                        f"{_bool_text(workflow.runs_untrusted_code)}; "
                        f"permissions={workflow.permissions}"
                    ),
                    rationale=(
                        "write-all is never permitted. release-write is "
                        "permitted only when trigger=tag and "
                        "runs_untrusted_code=false."
                    ),
                    next_action=(
                        "Use read-only permissions; reserve release-write for "
                        "trusted tag releases; never use write-all."
                    ),
                )
            )

        # S4: full environment logging with an active secret reference.
        if workflow.log_environment and active_refs:
            workflow_findings.append(
                Finding(
                    rule_id="S4",
                    decision=DECISION_FINDING,
                    severity="critical",
                    workflow_id=workflow.workflow_id,
                    evidence=(
                        "log_environment=true; "
                        f"active_secret_refs={_json_list(active_refs)}"
                    ),
                    rationale=(
                        "log_environment=true models full environment logging; "
                        "an active secret would be written to the log."
                    ),
                    next_action=(
                        "Disable log_environment and rotate any active secret "
                        "that may have been logged."
                    ),
                )
            )

        # S5: artifact publication of a configured sensitive path.
        matches = _s5_matches(workflow, sensitive_present)
        if matches:
            rendered = "; ".join(
                f"{json.dumps(pattern)} -> {json.dumps(path)}"
                for pattern, path in matches
            )
            workflow_findings.append(
                Finding(
                    rule_id="S5",
                    decision=DECISION_FINDING,
                    severity="high",
                    workflow_id=workflow.workflow_id,
                    evidence=(
                        f"artifact_paths={_json_list(workflow.artifact_paths)}; "
                        f"matches={rendered}"
                    ),
                    rationale=(
                        "An artifact pattern publishes a configured sensitive "
                        "path. Token state is ignored here so future credentials "
                        "in that path are protected too."
                    ),
                    next_action=(
                        "Remove sensitive paths and broad wildcards from "
                        "artifact_paths; publish only explicit non-sensitive "
                        "files."
                    ),
                )
            )

        # Unknown references are unresolved configuration, never invented
        # credentials and never treated as active for S2/S4.
        if unknown_refs:
            workflow_findings.append(
                Finding(
                    rule_id=UNRESOLVED_RULE_ID,
                    decision=DECISION_FINDING,
                    severity="medium",
                    workflow_id=workflow.workflow_id,
                    evidence=f"unknown_secret_refs={_json_list(unknown_refs)}",
                    rationale=(
                        "A secret_ref cannot be resolved in inventory. It is "
                        "reported as unresolved configuration, not as an active "
                        "credential."
                    ),
                    next_action=(
                        "Add the missing token to inventory or correct the "
                        "workflow reference."
                    ),
                )
            )

        decisions.extend(workflow_findings)

        if not workflow_findings:
            decisions.append(
                Finding(
                    rule_id=WORKFLOW_BENIGN_RULE_ID,
                    decision=DECISION_BENIGN,
                    severity="info",
                    workflow_id=workflow.workflow_id,
                    evidence=(
                        f"trigger={workflow.trigger}; "
                        f"runs_untrusted_code="
                        f"{_bool_text(workflow.runs_untrusted_code)}; "
                        f"permissions={workflow.permissions}; "
                        f"secret_refs={_json_list(refs)}; "
                        f"log_environment="
                        f"{_bool_text(workflow.log_environment)}; "
                        f"artifact_paths={_json_list(workflow.artifact_paths)}"
                    ),
                    rationale=(
                        "This workflow configuration passes S2-S5: permissions "
                        "are allowed for its trigger/untrusted combination, no "
                        "active secret is referenced by untrusted or logging "
                        "behavior, and no sensitive artifact is published. S1 "
                        "is evaluated separately at file level."
                    ),
                    next_action="No action; retain this configuration.",
                )
            )

    return decisions
