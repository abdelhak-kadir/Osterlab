"""Golden tests against both supplied snapshots and a synthetic third snapshot."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from auditor.api import audit_snapshot, report_json
from tests.helpers import TempDirCase, token, workflow

REPO_ROOT = Path(__file__).resolve().parent.parent
SNAPSHOT_ONE = REPO_ROOT / "inputs" / "snapshot-one"
SNAPSHOT_TWO = REPO_ROOT / "inputs" / "snapshot-two"


def decision_key(item: dict) -> tuple:
    return (
        item["rule_id"],
        item["decision"],
        item["workflow_id"],
        item["path"],
        item["line"],
        item["token_id"],
    )


def keys(report: dict, section: str) -> set[tuple]:
    return {decision_key(item) for item in report[section]}


def inventory_values(snapshot_dir: Path) -> list[str]:
    data = json.loads((snapshot_dir / "inventory.json").read_text(encoding="utf-8"))
    return [item["value"] for item in data["tokens"]]


def tree_hashes(root: Path) -> dict[str, str]:
    hashes = {}
    for path in sorted(root.rglob("*")):
        if path.is_file():
            hashes[path.relative_to(root).as_posix()] = hashlib.sha256(
                path.read_bytes()
            ).hexdigest()
    return hashes


class GoldenTests(TempDirCase):
    def test_snapshot_one_exact_decisions(self):
        report, summary = audit_snapshot(SNAPSHOT_ONE)

        self.assertEqual(report["snapshot"], "snapshot-one")
        self.assertEqual(report["counts"]["findings"], 5)
        self.assertEqual(report["counts"]["benign"], 3)
        self.assertEqual(report["counts"]["unresolved"], 0)
        self.assertEqual(
            report["counts"]["findings_by_severity"],
            {"critical": 3, "high": 2},
        )
        self.assertEqual(keys(report, "findings"), {
            ("S1", "finding", None, "app/env.txt", 2, "release-active"),
            ("S2", "finding", "pr-build", None, None, None),
            ("S3", "finding", "pr-build", None, None, None),
            ("S4", "finding", "pr-build", None, None, None),
            ("S5", "finding", "pr-build", None, None, None),
        })
        self.assertEqual(keys(report, "benign_decisions"), {
            ("S1", "benign", None, "docs/rotation.txt", 1, "old-docs"),
            ("S1", "benign", None, "tests/mock.txt", 2, "local-test"),
            ("WORKFLOW", "benign", "release", None, None, None),
        })

        s5 = next(item for item in report["findings"] if item["rule_id"] == "S5")
        self.assertIn('"app/env.txt" -> "app/env.txt"', s5["evidence"])
        self.assertIn("No raw token values", summary)

    def test_snapshot_two_exact_decisions(self):
        report, summary = audit_snapshot(SNAPSHOT_TWO)

        self.assertEqual(report["snapshot"], "snapshot-two")
        self.assertEqual(report["counts"]["findings"], 2)
        self.assertEqual(report["counts"]["benign"], 4)
        self.assertEqual(report["counts"]["unresolved"], 0)
        self.assertEqual(
            report["counts"]["findings_by_severity"],
            {"critical": 1, "high": 1},
        )
        self.assertEqual(keys(report, "findings"), {
            ("S1", "finding", None, "docs/rotation.txt", 2, "release-rotated"),
            ("S5", "finding", "pr-build", None, None, None),
        })
        self.assertEqual(keys(report, "benign_decisions"), {
            ("S1", "benign", None, "app/env.txt", 2, "release-active"),
            ("S1", "benign", None, "docs/rotation.txt", 1, "release-active"),
            ("S1", "benign", None, "tests/mock.txt", 2, "local-test"),
            ("WORKFLOW", "benign", "release", None, None, None),
        })

        s5 = next(item for item in report["findings"] if item["rule_id"] == "S5")
        self.assertIn('"app/*" -> "app/env.txt"', s5["evidence"])
        self.assertIn("No raw token values", summary)

    def test_outputs_never_contain_raw_token_values(self):
        for snapshot_dir in (SNAPSHOT_ONE, SNAPSHOT_TWO):
            with self.subTest(snapshot=snapshot_dir.name):
                report, summary = audit_snapshot(snapshot_dir)
                serialized = report_json(report)
                for value in inventory_values(snapshot_dir):
                    self.assertNotIn(value, serialized)
                    self.assertNotIn(value, summary)
                self.assertIn("[REDACTED:", serialized)

    def test_scope_excludes_metadata_and_lists_content(self):
        for snapshot_dir in (SNAPSHOT_ONE, SNAPSHOT_TWO):
            with self.subTest(snapshot=snapshot_dir.name):
                report, _ = audit_snapshot(snapshot_dir)
                self.assertEqual(
                    report["scope"]["scanned_files"],
                    [
                        "app/env.txt",
                        "build/report.txt",
                        "docs/rotation.txt",
                        "tests/mock.txt",
                    ],
                )
                self.assertEqual(
                    report["scope"]["not_scanned"],
                    ["inventory.json", "ci.json"],
                )

    def test_deterministic_output(self):
        first_report, first_summary = audit_snapshot(SNAPSHOT_ONE)
        second_report, second_summary = audit_snapshot(SNAPSHOT_ONE)
        self.assertEqual(report_json(first_report), report_json(second_report))
        self.assertEqual(first_summary, second_summary)

    def test_snapshot_is_not_modified(self):
        for snapshot_dir in (SNAPSHOT_ONE, SNAPSHOT_TWO):
            with self.subTest(snapshot=snapshot_dir.name):
                before = tree_hashes(snapshot_dir)
                audit_snapshot(snapshot_dir)
                after = tree_hashes(snapshot_dir)
                self.assertEqual(before, after)

    def test_third_synthetic_mutation_needs_no_code_change(self):
        root = self.snapshot(
            tokens=[
                token("new-active", "UNIT_NEW_ACTIVE_AAA"),
                token("new-revoked", "UNIT_NEW_REVOKED_BBB", "revoked_in_fixture"),
            ],
            workflows=[
                workflow(
                    "docs-publish",
                    runs_untrusted_code=True,
                    secret_refs=["new-active", "missing-ref"],
                    permissions="write-all",
                    log_environment=True,
                    artifact_paths=["docs/*"],
                ),
                workflow(
                    "trusted-release",
                    trigger="tag",
                    runs_untrusted_code=False,
                    secret_refs=["new-active"],
                    permissions="release-write",
                    log_environment=False,
                    artifact_paths=["build/report.txt"],
                ),
            ],
            files={
                "docs/rotation.txt": "Temporary: UNIT_NEW_ACTIVE_AAA\n",
                "app/env.txt": "Old: UNIT_NEW_REVOKED_BBB\n",
                "build/report.txt": "ok\n",
            },
        )
        report, summary = audit_snapshot(root)

        self.assertEqual(report["counts"]["findings"], 6)
        self.assertEqual(report["counts"]["benign"], 2)
        self.assertEqual(report["counts"]["unresolved"], 1)
        self.assertEqual(keys(report, "findings"), {
            ("S1", "finding", None, "docs/rotation.txt", 1, "new-active"),
            ("S2", "finding", "docs-publish", None, None, None),
            ("S3", "finding", "docs-publish", None, None, None),
            ("S4", "finding", "docs-publish", None, None, None),
            ("S5", "finding", "docs-publish", None, None, None),
            ("CONFIG-UNRESOLVED", "finding", "docs-publish", None, None, None),
        })
        self.assertEqual(keys(report, "benign_decisions"), {
            ("S1", "benign", None, "app/env.txt", 1, "new-revoked"),
            ("WORKFLOW", "benign", "trusted-release", None, None, None),
        })
        for value in ("UNIT_NEW_ACTIVE_AAA", "UNIT_NEW_REVOKED_BBB"):
            self.assertNotIn(value, report_json(report))
            self.assertNotIn(value, summary)
