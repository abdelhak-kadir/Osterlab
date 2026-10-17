"""Schema validation tests, including no-leak error messages."""

from __future__ import annotations

import json

from auditor.loader import SchemaError, load_snapshot
from tests.helpers import TempDirCase, token, workflow


class LoaderTests(TempDirCase):
    def write_raw(self, inventory, ci):
        root = self.tmp_path / "raw-snapshot"
        root.mkdir(parents=True, exist_ok=True)
        (root / "inventory.json").write_text(json.dumps(inventory), encoding="utf-8")
        (root / "ci.json").write_text(json.dumps(ci), encoding="utf-8")
        return root

    def valid_inventory(self):
        return {"schema_version": 1, "tokens": [token("one", "UNIT_ONE_VALUE")]}

    def valid_ci(self):
        return {"workflows": [workflow("one")]}

    def assert_schema_error(self, root):
        with self.assertRaises(SchemaError):
            load_snapshot(root)

    def test_valid_snapshot_loads(self):
        snapshot = load_snapshot(self.write_raw(self.valid_inventory(), self.valid_ci()))
        self.assertEqual(snapshot.name, "raw-snapshot")
        self.assertEqual(snapshot.tokens[0].token_id, "one")
        self.assertEqual(snapshot.workflows[0].workflow_id, "one")

    def test_missing_inventory_is_an_error(self):
        root = self.tmp_path / "missing"
        root.mkdir()
        (root / "ci.json").write_text(json.dumps(self.valid_ci()), encoding="utf-8")
        self.assert_schema_error(root)

    def test_missing_ci_is_an_error(self):
        root = self.tmp_path / "missing-ci"
        root.mkdir()
        (root / "inventory.json").write_text(
            json.dumps(self.valid_inventory()), encoding="utf-8"
        )
        self.assert_schema_error(root)

    def test_malformed_json_is_an_error(self):
        root = self.tmp_path / "malformed"
        root.mkdir()
        (root / "inventory.json").write_text("{not json", encoding="utf-8")
        (root / "ci.json").write_text(json.dumps(self.valid_ci()), encoding="utf-8")
        self.assert_schema_error(root)

    def test_inventory_schema_version_must_be_one(self):
        inventory = self.valid_inventory()
        inventory["schema_version"] = 2
        self.assert_schema_error(self.write_raw(inventory, self.valid_ci()))

    def test_duplicate_token_id_is_an_error(self):
        inventory = {
            "schema_version": 1,
            "tokens": [
                token("dupe", "UNIT_FIRST_VALUE"),
                token("dupe", "UNIT_SECOND_VALUE"),
            ],
        }
        self.assert_schema_error(self.write_raw(inventory, self.valid_ci()))

    def test_duplicate_token_value_is_an_error_without_leaking_it(self):
        inventory = {
            "schema_version": 1,
            "tokens": [
                token("first-id", "UNIT_DUPLICATE_VALUE"),
                token("second-id", "UNIT_DUPLICATE_VALUE"),
            ],
        }
        root = self.write_raw(inventory, self.valid_ci())
        with self.assertRaises(SchemaError) as raised:
            load_snapshot(root)
        message = str(raised.exception)
        self.assertIn("first-id", message)
        self.assertIn("second-id", message)
        self.assertNotIn("UNIT_DUPLICATE_VALUE", message)

    def test_invalid_state_is_an_error(self):
        inventory = {
            "schema_version": 1,
            "tokens": [token("bad-state", "UNIT_STATE_VALUE", "unknown_state")],
        }
        self.assert_schema_error(self.write_raw(inventory, self.valid_ci()))

    def test_multiline_token_value_is_an_error(self):
        inventory = {
            "schema_version": 1,
            "tokens": [token("multiline", "UNIT_LINE_ONE\nUNIT_LINE_TWO")],
        }
        self.assert_schema_error(self.write_raw(inventory, self.valid_ci()))

    def test_empty_token_id_is_an_error(self):
        inventory = {"schema_version": 1, "tokens": [token("", "UNIT_EMPTY_ID")]}
        self.assert_schema_error(self.write_raw(inventory, self.valid_ci()))

    def test_token_value_must_be_a_string(self):
        inventory = {"schema_version": 1, "tokens": [{"token_id": "x", "value": 5, "state": "test_only"}]}
        self.assert_schema_error(self.write_raw(inventory, self.valid_ci()))

    def test_invalid_trigger_is_an_error(self):
        ci = {"workflows": [workflow("bad", trigger="schedule")]}
        self.assert_schema_error(self.write_raw(self.valid_inventory(), ci))

    def test_invalid_permissions_is_an_error(self):
        ci = {"workflows": [workflow("bad", permissions="admin")]}
        self.assert_schema_error(self.write_raw(self.valid_inventory(), ci))

    def test_non_boolean_flag_is_an_error(self):
        candidate = workflow("bad")
        candidate["runs_untrusted_code"] = 1
        self.assert_schema_error(
            self.write_raw(self.valid_inventory(), {"workflows": [candidate]})
        )

    def test_non_string_ref_is_an_error(self):
        candidate = workflow("bad")
        candidate["secret_refs"] = [42]
        self.assert_schema_error(
            self.write_raw(self.valid_inventory(), {"workflows": [candidate]})
        )

    def test_duplicate_workflow_id_is_an_error(self):
        ci = {"workflows": [workflow("dupe"), workflow("dupe")]}
        self.assert_schema_error(self.write_raw(self.valid_inventory(), ci))

    def test_ci_schema_version_is_optional_but_validated(self):
        ci = self.valid_ci()
        ci["schema_version"] = 1
        snapshot = load_snapshot(self.write_raw(self.valid_inventory(), ci))
        self.assertEqual(len(snapshot.workflows), 1)

        ci["schema_version"] = 2
        self.assert_schema_error(self.write_raw(self.valid_inventory(), ci))

    def test_extra_fields_are_tolerated(self):
        inventory = self.valid_inventory()
        inventory["extra"] = {"future": True}
        inventory["tokens"][0]["extra"] = "allowed"
        ci = self.valid_ci()
        ci["extra"] = 1
        ci["workflows"][0]["extra"] = "allowed"
        snapshot = load_snapshot(self.write_raw(inventory, ci))
        self.assertEqual(snapshot.tokens[0].token_id, "one")

    def test_unknown_secret_ref_is_not_a_schema_error(self):
        ci = {"workflows": [workflow("one", secret_refs=["not-in-inventory"])]}
        snapshot = load_snapshot(self.write_raw(self.valid_inventory(), ci))
        self.assertEqual(snapshot.workflows[0].secret_refs, ("not-in-inventory",))

    def test_empty_collections_are_valid(self):
        snapshot = load_snapshot(
            self.write_raw(
                {"schema_version": 1, "tokens": []},
                {"workflows": []},
            )
        )
        self.assertEqual(snapshot.tokens, ())
        self.assertEqual(snapshot.workflows, ())
