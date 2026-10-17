"""Redaction tests: token_id traceability and no partial-value leaks."""

from __future__ import annotations

import unittest

from auditor.models import Token
from auditor.redact import redact_text


class RedactTests(unittest.TestCase):
    def test_replaces_values_and_preserves_token_id(self):
        tokens = [
            Token("alpha", "UNIT_ALPHA_AAA", "active_in_fixture"),
            Token("beta", "UNIT_BETA_BBB", "test_only"),
        ]
        result = redact_text("a=UNIT_ALPHA_AAA b=UNIT_BETA_BBB", tokens)
        self.assertEqual(
            result,
            "a=[REDACTED:alpha] b=[REDACTED:beta]",
        )

    def test_no_tokens_returns_text_unchanged(self):
        self.assertEqual(redact_text("plain text", []), "plain text")

    def test_longest_value_is_replaced_first(self):
        tokens = [
            Token("short", "UNIT_AAA", "active_in_fixture"),
            Token("long", "UNIT_AAA_EXT", "active_in_fixture"),
        ]
        result = redact_text("value=UNIT_AAA_EXT", tokens)
        self.assertEqual(result, "value=[REDACTED:long]")
        self.assertNotIn("UNIT_AAA", result)

    def test_input_order_does_not_matter(self):
        forward = [
            Token("one", "UNIT_ONE_VALUE", "active_in_fixture"),
            Token("two", "UNIT_TWO_VALUE", "revoked_in_fixture"),
        ]
        backward = list(reversed(forward))
        text = "UNIT_ONE_VALUE UNIT_TWO_VALUE"
        self.assertEqual(redact_text(text, forward), redact_text(text, backward))

    def test_regex_metacharacters_are_escaped(self):
        tokens = [Token("special", "UNIT.A+B", "active_in_fixture")]
        self.assertEqual(
            redact_text("x=UNIT.A+B", tokens),
            "x=[REDACTED:special]",
        )

    def test_absent_value_is_unchanged(self):
        tokens = [Token("other", "UNIT_OTHER_VALUE", "active_in_fixture")]
        self.assertEqual(redact_text("nothing here", tokens), "nothing here")

    def test_multiple_occurrences_are_all_replaced(self):
        tokens = [Token("repeat", "UNIT_REPEAT_VALUE", "active_in_fixture")]
        self.assertEqual(
            redact_text("UNIT_REPEAT_VALUE/UNIT_REPEAT_VALUE", tokens),
            "[REDACTED:repeat]/[REDACTED:repeat]",
        )
