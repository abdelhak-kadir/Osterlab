"""End-to-end CLI tests: documented commands, exit codes and no leaks."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

from tests.helpers import TempDirCase, workflow

REPO_ROOT = Path(__file__).resolve().parent.parent
SNAPSHOT_ONE = REPO_ROOT / "inputs" / "snapshot-one"


def run_cli(*args: str | Path) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, "-m", "auditor", *[str(arg) for arg in args]],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
    )


def inventory_values(snapshot_dir: Path) -> list[str]:
    data = json.loads((snapshot_dir / "inventory.json").read_text(encoding="utf-8"))
    return [item["value"] for item in data["tokens"]]


class CliTests(TempDirCase):
    def test_documented_command_succeeds_and_writes_both_files(self):
        out = self.tmp_path / "out"
        result = run_cli("inputs/snapshot-one", "--out", out)

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue((out / "findings.json").is_file())
        self.assertTrue((out / "summary.txt").is_file())
        self.assertIn("Risk findings: 5", result.stdout)
        self.assertIn("Benign decisions: 3", result.stdout)

        findings_text = (out / "findings.json").read_text(encoding="utf-8")
        summary_text = (out / "summary.txt").read_text(encoding="utf-8")
        decoded = json.loads(findings_text)
        self.assertEqual(decoded["counts"]["findings"], 5)
        for value in inventory_values(SNAPSHOT_ONE):
            self.assertNotIn(value, result.stdout)
            self.assertNotIn(value, result.stderr)
            self.assertNotIn(value, findings_text)
            self.assertNotIn(value, summary_text)

    def test_fail_on_findings_returns_one_but_still_writes_outputs(self):
        out = self.tmp_path / "out"
        result = run_cli(
            "inputs/snapshot-one", "--out", out, "--fail-on-findings"
        )
        self.assertEqual(result.returncode, 1)
        self.assertTrue((out / "findings.json").is_file())

    def test_fail_on_findings_returns_zero_when_clean(self):
        root = self.snapshot(workflows=[workflow("clean")])
        out = self.tmp_path / "clean-out"
        result = run_cli(root, "--out", out, "--fail-on-findings")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("Risk findings: 0", result.stdout)

    def test_out_inside_snapshot_is_rejected_without_writing(self):
        root = self.snapshot(workflows=[])
        out = root / "out"
        result = run_cli(root, "--out", out)
        self.assertEqual(result.returncode, 2)
        self.assertIn("must not be inside the snapshot", result.stderr)
        self.assertFalse(out.exists())

    def test_missing_snapshot_returns_two(self):
        result = run_cli(self.tmp_path / "does-not-exist", "--out", self.tmp_path / "out")
        self.assertEqual(result.returncode, 2)
        self.assertIn("snapshot directory not found", result.stderr)

    def test_invalid_schema_returns_two(self):
        broken = self.tmp_path / "broken"
        broken.mkdir()
        result = run_cli(broken, "--out", self.tmp_path / "out")
        self.assertEqual(result.returncode, 2)
        self.assertIn("missing required file", result.stderr)

    def test_version_flag(self):
        result = run_cli("--version")
        self.assertEqual(result.returncode, 0)
        self.assertIn("pinebuild-auditor", result.stdout)
