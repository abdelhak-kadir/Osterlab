"""Synthetic fixtures for unit tests.

These values are intentionally unrelated to the supplied snapshots so the test
source never contains a real fixture marker.
"""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path


def token(token_id: str, value: str, state: str = "active_in_fixture") -> dict:
    return {"token_id": token_id, "value": value, "state": state}


def workflow(
    workflow_id: str,
    *,
    trigger: str = "pull_request",
    runs_untrusted_code: bool = False,
    secret_refs: list[str] | None = None,
    permissions: str = "read-only",
    log_environment: bool = False,
    artifact_paths: list[str] | None = None,
) -> dict:
    return {
        "workflow_id": workflow_id,
        "trigger": trigger,
        "runs_untrusted_code": runs_untrusted_code,
        "secret_refs": [] if secret_refs is None else secret_refs,
        "permissions": permissions,
        "log_environment": log_environment,
        "artifact_paths": [] if artifact_paths is None else artifact_paths,
    }


def make_snapshot(root: Path, tokens=None, workflows=None, files=None) -> Path:
    root.mkdir(parents=True, exist_ok=True)
    (root / "inventory.json").write_text(
        json.dumps({"schema_version": 1, "tokens": tokens or []}),
        encoding="utf-8",
    )
    (root / "ci.json").write_text(
        json.dumps({"workflows": workflows or []}),
        encoding="utf-8",
    )
    for relative_path, text in (files or {}).items():
        path = root / relative_path
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
    return root


def decisions_by_rule(decisions, rule_id=None, decision=None):
    result = list(decisions)
    if rule_id is not None:
        result = [item for item in result if item.rule_id == rule_id]
    if decision is not None:
        result = [item for item in result if item.decision == decision]
    return result


class TempDirCase(unittest.TestCase):
    """Give each test a private directory and unique snapshot names."""

    def setUp(self):
        self._tempdir = tempfile.TemporaryDirectory()
        self.tmp_path = Path(self._tempdir.name)
        self._snapshot_count = 0

    def tearDown(self):
        self._tempdir.cleanup()

    def snapshot(self, tokens=None, workflows=None, files=None) -> Path:
        self._snapshot_count += 1
        root = self.tmp_path / f"snapshot-{self._snapshot_count}"
        return make_snapshot(root, tokens=tokens, workflows=workflows, files=files)
