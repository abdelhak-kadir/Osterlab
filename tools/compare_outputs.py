#!/usr/bin/env python3
"""Compare two findings.json reports without re-auditing anything.

Usage:
    python3 tools/compare_outputs.py outputs/snapshot-one/findings.json \
        outputs/snapshot-two/findings.json

The reports contain no raw token values, so the comparison is safe to capture.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path


def decision_key(item: dict) -> tuple:
    return (
        item["rule_id"],
        item["decision"],
        item["workflow_id"],
        item["path"],
        item["line"],
        item["token_id"],
    )


def label(item: dict) -> str:
    if item.get("path"):
        location = item["path"]
        if item.get("line") is not None:
            location += f":{item['line']}"
    else:
        location = f"workflow={item.get('workflow_id')}"
    if item.get("token_id"):
        location += f" (token_id={item['token_id']})"
    return f"{item['rule_id']} {location} [{item['severity']}]"


def render_section(title: str, items: list[dict]) -> list[str]:
    lines = [title]
    if not items:
        lines.append("  (none)")
    for item in items:
        lines.append(f"  - {label(item)}")
    return lines


def main(argv: list[str]) -> int:
    if len(argv) != 3:
        print(
            "usage: python3 tools/compare_outputs.py OLD/findings.json "
            "NEW/findings.json",
            file=sys.stderr,
        )
        return 2

    try:
        old = json.loads(Path(argv[1]).read_text(encoding="utf-8"))
        new = json.loads(Path(argv[2]).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    old_findings = {decision_key(item): item for item in old["findings"]}
    new_findings = {decision_key(item): item for item in new["findings"]}
    old_benign = {decision_key(item): item for item in old["benign_decisions"]}
    new_benign = {decision_key(item): item for item in new["benign_decisions"]}

    resolved = [
        old_findings[key] for key in sorted(old_findings.keys() - new_findings.keys())
    ]
    introduced = [
        new_findings[key] for key in sorted(new_findings.keys() - old_findings.keys())
    ]
    unchanged = [
        old_findings[key] for key in sorted(old_findings.keys() & new_findings.keys())
    ]
    benign_added = [
        new_benign[key] for key in sorted(new_benign.keys() - old_benign.keys())
    ]
    benign_removed = [
        old_benign[key] for key in sorted(old_benign.keys() - new_benign.keys())
    ]

    lines = [
        "PineBuild snapshot comparison",
        (
            f"OLD: {old['snapshot']} "
            f"(findings={old['counts']['findings']}, "
            f"benign={old['counts']['benign']}, "
            f"unresolved={old['counts']['unresolved']})"
        ),
        (
            f"NEW: {new['snapshot']} "
            f"(findings={new['counts']['findings']}, "
            f"benign={new['counts']['benign']}, "
            f"unresolved={new['counts']['unresolved']})"
        ),
        "",
    ]
    lines.extend(render_section("RISK FINDINGS RESOLVED (OLD only)", resolved))
    lines.append("")
    lines.extend(render_section("RISK FINDINGS INTRODUCED (NEW only)", introduced))
    lines.append("")
    lines.extend(render_section("RISK FINDINGS UNCHANGED", unchanged))
    lines.append("")
    lines.extend(render_section("BENIGN DECISIONS ADDED (NEW only)", benign_added))
    lines.append("")
    lines.extend(render_section("BENIGN DECISIONS REMOVED (OLD only)", benign_removed))
    print("\n".join(lines))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
