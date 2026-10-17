"""Programmatic audit API used by the CLI, tests and tools."""

from __future__ import annotations

import json
from pathlib import Path

from .loader import load_snapshot
from .report import build_report, summary_text
from .rules import evaluate_workflows
from .scanner import scan_text


def audit_snapshot(snapshot_dir: str | Path) -> tuple[dict, str]:
    """Audit one snapshot and return ``(report_dict, summary_text)``.

    The function is read-only with respect to the snapshot: it only reads
    inventory.json, ci.json and the four content directories.
    """
    snapshot = load_snapshot(Path(snapshot_dir))
    decisions = scan_text(snapshot) + evaluate_workflows(snapshot)
    report = build_report(snapshot, decisions)
    return report, summary_text(report)


def report_json(report: dict) -> str:
    """Serialize a report deterministically (stable keys, ASCII, newline)."""
    return json.dumps(report, indent=2, sort_keys=True, ensure_ascii=True) + "\n"


def write_outputs(report: dict, summary: str, out_dir: str | Path) -> tuple[Path, Path]:
    """Write findings.json and summary.txt, returning their paths."""
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    findings_path = out / "findings.json"
    summary_path = out / "summary.txt"
    with open(findings_path, "w", encoding="utf-8", newline="\n") as handle:
        handle.write(report_json(report))
    with open(summary_path, "w", encoding="utf-8", newline="\n") as handle:
        handle.write(summary)
    return findings_path, summary_path
