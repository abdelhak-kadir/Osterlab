"""S2-S5 tests: exact decisions, intersections, wildcards and unresolved refs."""

from __future__ import annotations

from auditor.loader import load_snapshot
from auditor.models import Workflow
from auditor.rules import evaluate_workflows, permissions_allowed
from tests.helpers import TempDirCase, decisions_by_rule, token, workflow

ACTIVE = token("active", "UNIT_ACTIVE_TOKEN")
REVOKED = token("revoked", "UNIT_REVOKED_TOKEN", "revoked_in_fixture")
TEST_ONLY = token("test", "UNIT_TEST_TOKEN", "test_only")


class RulesTests(TempDirCase):
    def evaluate(self, tokens=None, workflows=None, files=None):
        root = self.snapshot(
            tokens=tokens or [], workflows=workflows or [], files=files or {}
        )
        return evaluate_workflows(load_snapshot(root))

    # S3 ------------------------------------------------------------------
    def test_s3_permission_trigger_table(self):
        cases = 0
        for trigger in ("pull_request", "tag"):
            for untrusted in (True, False):
                for permissions in ("read-only", "release-write", "write-all"):
                    with self.subTest(
                        trigger=trigger,
                        untrusted=untrusted,
                        permissions=permissions,
                    ):
                        candidate = workflow(
                            "candidate",
                            trigger=trigger,
                            runs_untrusted_code=untrusted,
                            permissions=permissions,
                        )
                        decisions = self.evaluate(workflows=[candidate])
                        s3 = decisions_by_rule(decisions, "S3")
                        allowed = permissions == "read-only" or (
                            permissions == "release-write"
                            and trigger == "tag"
                            and not untrusted
                        )
                        self.assertEqual(bool(s3), not allowed)
                        if not allowed:
                            self.assertEqual(s3[0].decision, "finding")
                            self.assertEqual(s3[0].severity, "high")
                        cases += 1
        self.assertEqual(cases, 12)

    def test_permissions_allowed_helper(self):
        def candidate(trigger, untrusted, permissions):
            return Workflow(
                workflow_id="candidate",
                trigger=trigger,
                runs_untrusted_code=untrusted,
                secret_refs=(),
                permissions=permissions,
                log_environment=False,
                artifact_paths=(),
            )

        self.assertTrue(permissions_allowed(candidate("pull_request", False, "read-only")))
        self.assertTrue(permissions_allowed(candidate("pull_request", True, "read-only")))
        self.assertTrue(permissions_allowed(candidate("tag", False, "read-only")))
        self.assertTrue(permissions_allowed(candidate("tag", True, "read-only")))
        self.assertTrue(permissions_allowed(candidate("tag", False, "release-write")))
        self.assertFalse(permissions_allowed(candidate("tag", True, "release-write")))
        self.assertFalse(
            permissions_allowed(candidate("pull_request", False, "release-write"))
        )
        self.assertFalse(
            permissions_allowed(candidate("pull_request", True, "release-write"))
        )
        self.assertFalse(permissions_allowed(candidate("tag", False, "write-all")))
        self.assertFalse(
            permissions_allowed(candidate("pull_request", False, "write-all"))
        )

    # S2 ------------------------------------------------------------------
    def test_s2_fires_for_untrusted_code_with_active_ref(self):
        decisions = self.evaluate(
            tokens=[ACTIVE],
            workflows=[
                workflow(
                    "untrusted",
                    runs_untrusted_code=True,
                    secret_refs=["active"],
                )
            ],
        )
        s2 = decisions_by_rule(decisions, "S2")
        self.assertEqual(len(s2), 1)
        self.assertEqual(s2[0].decision, "finding")
        self.assertEqual(s2[0].severity, "critical")
        self.assertIn('active_secret_refs=["active"]', s2[0].evidence)
        self.assertIn("does not prove exploitation", s2[0].rationale)

    def test_s2_ignores_revoked_test_only_and_empty_refs(self):
        for refs, expected in (
            (["revoked"], False),
            (["test"], False),
            ([], False),
            (["active"], True),
        ):
            with self.subTest(refs=refs):
                decisions = self.evaluate(
                    tokens=[ACTIVE, REVOKED, TEST_ONLY],
                    workflows=[
                        workflow(
                            "untrusted",
                            runs_untrusted_code=True,
                            secret_refs=refs,
                        )
                    ],
                )
                self.assertEqual(bool(decisions_by_rule(decisions, "S2")), expected)

    def test_s2_requires_untrusted_code(self):
        decisions = self.evaluate(
            tokens=[ACTIVE],
            workflows=[
                workflow(
                    "trusted",
                    trigger="tag",
                    runs_untrusted_code=False,
                    secret_refs=["active"],
                    permissions="release-write",
                )
            ],
        )
        self.assertEqual(decisions_by_rule(decisions, "S2"), [])

    def test_s2_mixed_refs_reports_only_active_evidence(self):
        decisions = self.evaluate(
            tokens=[ACTIVE, REVOKED, TEST_ONLY],
            workflows=[
                workflow(
                    "mixed",
                    runs_untrusted_code=True,
                    secret_refs=["revoked", "active", "test", "missing"],
                )
            ],
        )
        s2 = decisions_by_rule(decisions, "S2")
        unresolved = decisions_by_rule(decisions, "CONFIG-UNRESOLVED")
        self.assertEqual(len(s2), 1)
        self.assertIn('active_secret_refs=["active"]', s2[0].evidence)
        self.assertNotIn("revoked", s2[0].evidence)
        self.assertNotIn("test", s2[0].evidence)
        self.assertEqual(len(unresolved), 1)
        self.assertIn('unknown_secret_refs=["missing"]', unresolved[0].evidence)

    # S4 ------------------------------------------------------------------
    def test_s4_fires_for_logging_with_active_ref(self):
        decisions = self.evaluate(
            tokens=[ACTIVE],
            workflows=[
                workflow(
                    "logger",
                    log_environment=True,
                    secret_refs=["active"],
                )
            ],
        )
        s4 = decisions_by_rule(decisions, "S4")
        self.assertEqual(len(s4), 1)
        self.assertEqual(s4[0].severity, "critical")
        self.assertIn('active_secret_refs=["active"]', s4[0].evidence)

    def test_s4_ignores_non_active_and_empty_refs(self):
        for refs, expected in (
            (["revoked"], False),
            (["test"], False),
            ([], False),
            (["active"], True),
        ):
            with self.subTest(refs=refs):
                decisions = self.evaluate(
                    tokens=[ACTIVE, REVOKED, TEST_ONLY],
                    workflows=[
                        workflow("logger", log_environment=True, secret_refs=refs)
                    ],
                )
                self.assertEqual(bool(decisions_by_rule(decisions, "S4")), expected)

    def test_s4_has_no_trusted_tag_exception(self):
        decisions = self.evaluate(
            tokens=[ACTIVE],
            workflows=[
                workflow(
                    "trusted-but-logging",
                    trigger="tag",
                    runs_untrusted_code=False,
                    permissions="release-write",
                    secret_refs=["active"],
                    log_environment=True,
                )
            ],
        )
        self.assertEqual(len(decisions_by_rule(decisions, "S4")), 1)
        self.assertEqual(decisions_by_rule(decisions, "S3"), [])

    def test_s4_does_not_fire_without_logging(self):
        decisions = self.evaluate(
            tokens=[ACTIVE],
            workflows=[workflow("quiet", log_environment=False, secret_refs=["active"])],
        )
        self.assertEqual(decisions_by_rule(decisions, "S4"), [])

    # S5 ------------------------------------------------------------------
    def test_s5_wildcard_matches_sensitive_path(self):
        decisions = self.evaluate(
            files={"app/env.txt": "text\n", "build/report.txt": "text\n"},
            workflows=[
                workflow("publisher", artifact_paths=["app/*", "build/report.txt"])
            ],
        )
        s5 = decisions_by_rule(decisions, "S5")
        self.assertEqual(len(s5), 1)
        self.assertEqual(s5[0].decision, "finding")
        self.assertEqual(s5[0].severity, "high")
        self.assertIn('"app/*" -> "app/env.txt"', s5[0].evidence)

    def test_s5_non_sensitive_wildcard_does_not_match(self):
        decisions = self.evaluate(
            files={"build/report.txt": "text\n", "app/other.txt": "text\n"},
            workflows=[workflow("publisher", artifact_paths=["build/*", "app/*"])],
        )
        # app/* matches app/other.txt, but that is not a configured sensitive
        # path; build/report.txt is also not sensitive. No S5 finding.
        self.assertEqual(decisions_by_rule(decisions, "S5"), [])

    def test_s5_requires_whole_path_match(self):
        decisions = self.evaluate(
            files={"app/env.txt": "text\n"},
            workflows=[workflow("publisher", artifact_paths=["env.txt", "app/"])],
        )
        self.assertEqual(decisions_by_rule(decisions, "S5"), [])

    def test_s5_is_case_sensitive(self):
        decisions = self.evaluate(
            files={"app/env.txt": "text\n"},
            workflows=[workflow("publisher", artifact_paths=["APP/ENV.TXT"])],
        )
        self.assertEqual(decisions_by_rule(decisions, "S5"), [])

    def test_s5_star_matches_both_sensitive_paths(self):
        decisions = self.evaluate(
            files={
                "app/env.txt": "text\n",
                "docs/rotation.txt": "text\n",
            },
            workflows=[workflow("publisher", artifact_paths=["*"])],
        )
        s5 = decisions_by_rule(decisions, "S5")
        self.assertEqual(len(s5), 1)
        self.assertIn('"app/env.txt"', s5[0].evidence)
        self.assertIn('"docs/rotation.txt"', s5[0].evidence)

    def test_s5_aggregates_multiple_patterns_in_one_finding(self):
        decisions = self.evaluate(
            files={"app/env.txt": "text\n", "docs/rotation.txt": "text\n"},
            workflows=[workflow("publisher", artifact_paths=["app/*", "docs/*"])],
        )
        s5 = decisions_by_rule(decisions, "S5")
        self.assertEqual(len(s5), 1)
        self.assertIn('"app/*" -> "app/env.txt"', s5[0].evidence)
        self.assertIn('"docs/*" -> "docs/rotation.txt"', s5[0].evidence)

    def test_s5_ignores_token_state(self):
        decisions = self.evaluate(
            tokens=[REVOKED],
            files={"app/env.txt": "UNIT_REVOKED_TOKEN\n"},
            workflows=[workflow("publisher", artifact_paths=["app/*"])],
        )
        self.assertEqual(len(decisions_by_rule(decisions, "S5")), 1)

    def test_s5_does_not_fire_when_sensitive_file_is_absent(self):
        decisions = self.evaluate(
            files={"build/report.txt": "text\n"},
            workflows=[workflow("publisher", artifact_paths=["app/*", "docs/*"])],
        )
        self.assertEqual(decisions_by_rule(decisions, "S5"), [])

    # Unresolved refs and benign workflow evidence -------------------------
    def test_unknown_ref_is_unresolved_configuration_not_active(self):
        decisions = self.evaluate(
            workflows=[
                workflow(
                    "mystery",
                    runs_untrusted_code=True,
                    log_environment=True,
                    secret_refs=["does-not-exist"],
                )
            ],
        )
        self.assertEqual(decisions_by_rule(decisions, "S2"), [])
        self.assertEqual(decisions_by_rule(decisions, "S4"), [])
        unresolved = decisions_by_rule(decisions, "CONFIG-UNRESOLVED")
        self.assertEqual(len(unresolved), 1)
        self.assertEqual(unresolved[0].severity, "medium")
        self.assertIn('unknown_secret_refs=["does-not-exist"]', unresolved[0].evidence)

    def test_clean_workflow_emits_benign_decision(self):
        decisions = self.evaluate(
            workflows=[workflow("clean", permissions="read-only")],
        )
        benign = decisions_by_rule(decisions, "WORKFLOW", "benign")
        self.assertEqual(len(benign), 1)
        self.assertEqual(benign[0].workflow_id, "clean")
        self.assertEqual(benign[0].severity, "info")
        self.assertIn("passes S2-S5", benign[0].rationale)

    def test_trusted_release_with_active_secret_is_benign(self):
        decisions = self.evaluate(
            tokens=[ACTIVE],
            workflows=[
                workflow(
                    "trusted-release",
                    trigger="tag",
                    runs_untrusted_code=False,
                    permissions="release-write",
                    secret_refs=["active"],
                    log_environment=False,
                    artifact_paths=["build/report.txt"],
                )
            ],
            files={"build/report.txt": "text\n"},
        )
        self.assertEqual(decisions_by_rule(decisions, "S2"), [])
        self.assertEqual(decisions_by_rule(decisions, "S3"), [])
        self.assertEqual(decisions_by_rule(decisions, "S4"), [])
        self.assertEqual(decisions_by_rule(decisions, "S5"), [])
        self.assertEqual(len(decisions_by_rule(decisions, "WORKFLOW", "benign")), 1)

    def test_violating_workflow_has_no_benign_decision(self):
        for candidate in (
            workflow("bad-perm", permissions="write-all"),
            workflow("bad-artifact", artifact_paths=["app/*"]),
            workflow("bad-ref", secret_refs=["missing"]),
        ):
            with self.subTest(workflow=candidate["workflow_id"]):
                decisions = self.evaluate(
                    files={"app/env.txt": "text\n"},
                    workflows=[candidate],
                )
                self.assertEqual(decisions_by_rule(decisions, "WORKFLOW"), [])
