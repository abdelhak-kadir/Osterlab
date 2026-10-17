"""Deterministic machine-readable report and readable summary."""

from __future__ import annotations

from .models import DECISION_BENIGN, DECISION_FINDING, Finding, Snapshot
from .policy import NOT_SCANNED, POLICY_VERSION, SCANNED_DIRS, SENSITIVE_PATHS
from .rules import UNRESOLVED_RULE_ID
from .scanner import list_content_files

SEVERITY_ORDER = ("critical", "high", "medium", "low", "info")


def _sort_key(finding: Finding) -> tuple:
    return finding.sort_key()


def build_report(snapshot: Snapshot, decisions: list[Finding]) -> dict:
    """Build the stable JSON-ready report.

    Risk findings and benign decisions are separate arrays so counts are
    unambiguous; every entry carries the same evidence fields.
    """
    findings = sorted(
        (item for item in decisions if item.decision == DECISION_FINDING),
        key=_sort_key,
    )
    benign = sorted(
        (item for item in decisions if item.decision == DECISION_BENIGN),
        key=_sort_key,
    )

    by_severity: dict[str, int] = {}
    by_rule: dict[str, int] = {}
    for finding in findings:
        by_severity[finding.severity] = by_severity.get(finding.severity, 0) + 1
        by_rule[finding.rule_id] = by_rule.get(finding.rule_id, 0) + 1

    counts = {
        "findings": len(findings),
        "benign": len(benign),
        "unresolved": sum(
            1 for finding in findings if finding.rule_id == UNRESOLVED_RULE_ID
        ),
        "findings_by_severity": {
            severity: by_severity[severity]
            for severity in SEVERITY_ORDER
            if by_severity.get(severity)
        },
        "findings_by_rule": dict(sorted(by_rule.items())),
    }

    return {
        "schema_version": 1,
        "auditor": "pinebuild-auditor",
        "ruleset": POLICY_VERSION,
        "snapshot": snapshot.name,
        "scope": {
            "scanned_dirs": list(SCANNED_DIRS),
            "scanned_files": list_content_files(snapshot.root),
            "sensitive_paths": list(SENSITIVE_PATHS),
            "not_scanned": list(NOT_SCANNED),
        },
        "counts": counts,
        "findings": [finding.to_dict() for finding in findings],
        "benign_decisions": [decision.to_dict() for decision in benign],
    }


def _location(item: dict) -> str:
    if item.get("path"):
        location = item["path"]
        if item.get("line") is not None:
            location += f":{item['line']}"
    else:
        location = f"workflow={item.get('workflow_id')}"
    if item.get("token_id"):
        location += f" (token_id={item['token_id']})"
    return location


def _severity_rank(item: dict) -> int:
    try:
        return SEVERITY_ORDER.index(item["severity"])
    except ValueError:
        return len(SEVERITY_ORDER)


def summary_text(report: dict) -> str:
    """Render a readable, deterministic summary with no raw token values."""
    counts = report["counts"]
    lines: list[str] = [
        "PineBuild offline secrets/CI audit",
        f"Snapshot: {report['snapshot']}",
        f"Ruleset: {report['ruleset']}",
        "",
        f"Risk findings: {counts['findings']}",
    ]
    for severity in SEVERITY_ORDER:
        amount = counts["findings_by_severity"].get(severity, 0)
        if amount:
            lines.append(f"  {severity.capitalize()}: {amount}")
    lines.extend(
        [
            f"Benign decisions: {counts['benign']}",
            f"Unresolved refs: {counts['unresolved']}",
            "",
            "RISK FINDINGS",
        ]
    )

    findings = sorted(
        report["findings"],
        key=lambda item: (
            _severity_rank(item),
            item["rule_id"],
            item.get("path") or "",
            item.get("workflow_id") or "",
            item.get("line") or 0,
            item.get("token_id") or "",
        ),
    )
    if not findings:
        lines.append("  (none)")
    for index, item in enumerate(findings, start=1):
        lines.append(
            f"{index}. [{item['severity'].upper()}] {item['rule_id']} "
            f"{_location(item)}"
        )
        lines.append(f"   evidence: {item['evidence']}")
        lines.append(f"   why: {item['rationale']}")
        lines.append(f"   next: {item['next_action']}")

    lines.extend(["", "BENIGN DECISIONS"])
    benign = sorted(
        report["benign_decisions"],
        key=lambda item: (
            item["rule_id"],
            item.get("path") or "",
            item.get("workflow_id") or "",
            item.get("line") or 0,
            item.get("token_id") or "",
        ),
    )
    if not benign:
        lines.append("  (none)")
    for index, item in enumerate(benign, start=1):
        lines.append(f"{index}. [BENIGN] {item['rule_id']} {_location(item)}")
        lines.append(f"   evidence: {item['evidence']}")
        lines.append(f"   why: {item['rationale']}")
        lines.append(f"   next: {item['next_action']}")

    lines.extend(
        [
            "",
            "NOTE: No raw token values are printed.",
            "[REDACTED:<token_id>] preserves traceability to inventory.",
        ]
    )
    return "\n".join(lines).rstrip() + "\n"
