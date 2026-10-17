"""S1 tests: active detection, state-based suppression and redaction."""

from __future__ import annotations

import os

from auditor.loader import load_snapshot
from auditor.scanner import list_content_files, scan_text
from tests.helpers import TempDirCase, token


class ScannerTests(TempDirCase):
    def scan(self, tokens=None, files=None):
        root = self.snapshot(tokens=tokens or [], workflows=[], files=files or {})
        return scan_text(load_snapshot(root))

    def test_active_token_in_docs_is_a_finding(self):
        decisions = self.scan(
            tokens=[token("active-doc", "UNIT_ACTIVE_AAA")],
            files={"docs/note.txt": "intro\nvalue UNIT_ACTIVE_AAA\n"},
        )
        self.assertEqual(len(decisions), 1)
        decision = decisions[0]
        self.assertEqual(decision.rule_id, "S1")
        self.assertEqual(decision.decision, "finding")
        self.assertEqual(decision.severity, "critical")
        self.assertEqual(decision.path, "docs/note.txt")
        self.assertEqual(decision.line, 2)
        self.assertEqual(decision.token_id, "active-doc")
        self.assertIn("[REDACTED:active-doc]", decision.evidence)
        self.assertNotIn("UNIT_ACTIVE_AAA", decision.evidence)

    def test_filename_does_not_exempt_active_token(self):
        decisions = self.scan(
            tokens=[token("active-test", "UNIT_ACTIVE_BBB")],
            files={"tests/mock.txt": "API_TOKEN=UNIT_ACTIVE_BBB\n"},
        )
        self.assertEqual(len(decisions), 1)
        self.assertEqual(decisions[0].decision, "finding")
        self.assertEqual(decisions[0].path, "tests/mock.txt")

    def test_revoked_and_test_only_are_benign(self):
        decisions = self.scan(
            tokens=[
                token("test-marker", "UNIT_TEST_CCC", "test_only"),
                token("revoked-marker", "UNIT_REVOKED_DDD", "revoked_in_fixture"),
            ],
            files={
                "tests/mock.txt": "UNIT_TEST_CCC\n",
                "docs/old.txt": "UNIT_REVOKED_DDD\n",
            },
        )
        self.assertEqual(len(decisions), 2)
        self.assertEqual({item.decision for item in decisions}, {"benign"})
        self.assertEqual(
            {item.token_id for item in decisions},
            {"test-marker", "revoked-marker"},
        )
        self.assertEqual({item.severity for item in decisions}, {"info"})
        for item in decisions:
            self.assertEqual(item.rule_id, "S1")
            self.assertIn(f"[REDACTED:{item.token_id}]", item.evidence)
            self.assertNotIn("UNIT_", item.evidence)

    def test_inventory_and_ci_are_not_scanned(self):
        # The active value is present in inventory.json, but no content file
        # contains it. If inventory were scanned, this would be a finding.
        decisions = self.scan(
            tokens=[token("active-only-in-inventory", "UNIT_INVENTORY_EEE")],
            files={},
        )
        self.assertEqual(decisions, [])

    def test_longest_token_wins_when_values_overlap(self):
        decisions = self.scan(
            tokens=[
                token("short", "UNIT_AAA"),
                token("long", "UNIT_AAA_EXT"),
            ],
            files={"app/config.txt": "UNIT_AAA_EXT\n"},
        )
        self.assertEqual(len(decisions), 1)
        self.assertEqual(decisions[0].token_id, "long")

    def test_repeated_occurrence_on_one_line_is_one_decision(self):
        decisions = self.scan(
            tokens=[token("repeat", "UNIT_REPEAT_FFF")],
            files={"app/config.txt": "UNIT_REPEAT_FFF UNIT_REPEAT_FFF\n"},
        )
        self.assertEqual(len(decisions), 1)
        self.assertEqual(decisions[0].line, 1)

    def test_two_lines_produce_two_decisions(self):
        decisions = self.scan(
            tokens=[token("twice", "UNIT_TWICE_GGG")],
            files={"app/config.txt": "UNIT_TWICE_GGG\nsafe\nUNIT_TWICE_GGG\n"},
        )
        self.assertEqual(len(decisions), 2)
        self.assertEqual([item.line for item in decisions], [1, 3])

    def test_two_tokens_on_one_line_are_both_reported_and_redacted(self):
        decisions = self.scan(
            tokens=[
                token("active-one", "UNIT_A_HHH"),
                token("revoked-two", "UNIT_R_III", "revoked_in_fixture"),
            ],
            files={"docs/both.txt": "UNIT_A_HHH and UNIT_R_III\n"},
        )
        self.assertEqual(len(decisions), 2)
        for item in decisions:
            self.assertIn("[REDACTED:active-one]", item.evidence)
            self.assertIn("[REDACTED:revoked-two]", item.evidence)
            self.assertNotIn("UNIT_A_HHH", item.evidence)
            self.assertNotIn("UNIT_R_III", item.evidence)

    def test_crlf_line_numbers(self):
        decisions = self.scan(
            tokens=[token("crlf", "UNIT_CRLF_JJJ")],
            files={"app/config.txt": "first\r\nUNIT_CRLF_JJJ\r\n"},
        )
        self.assertEqual(len(decisions), 1)
        self.assertEqual(decisions[0].line, 2)

    def test_missing_content_directories_are_fine(self):
        root = self.snapshot(tokens=[], workflows=[], files={})
        self.assertEqual(list_content_files(root), [])
        self.assertEqual(scan_text(load_snapshot(root)), [])

    def test_symlinked_content_is_skipped(self):
        root = self.snapshot(tokens=[token("outside", "UNIT_OUTSIDE_KKK")], workflows=[])
        app = root / "app"
        app.mkdir(parents=True, exist_ok=True)
        outside = self.tmp_path / "outside.txt"
        outside.write_text("UNIT_OUTSIDE_KKK\n", encoding="utf-8")
        link = app / "link.txt"
        try:
            os.symlink(outside, link)
        except (OSError, NotImplementedError):
            self.skipTest("symlinks are unavailable on this platform")
        self.assertEqual(scan_text(load_snapshot(root)), [])
        self.assertNotIn("app/link.txt", list_content_files(root))
