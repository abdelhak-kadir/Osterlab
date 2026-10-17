"""Load and validate snapshot metadata without ever executing it.

Validation is strict about the documented schema but tolerant of unknown extra
fields, so a newer same-schema snapshot still loads.  Error messages name the
field and token_id/workflow_id; they never include a token value.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .models import (
    PERMISSIONS,
    TOKEN_STATES,
    TRIGGERS,
    Snapshot,
    Token,
    Workflow,
)


class SchemaError(Exception):
    """Raised when snapshot input does not match the documented schema."""


def _fail(message: str) -> None:
    raise SchemaError(message)


def _read_json(path: Path, label: str) -> Any:
    try:
        raw = path.read_text(encoding="utf-8")
    except FileNotFoundError:
        _fail(f"missing required file: {label}")
    except (OSError, UnicodeError) as exc:
        _fail(f"cannot read {label}: {exc}")

    try:
        return json.loads(raw)
    except json.JSONDecodeError as exc:
        # Only position information is reported; file content is not echoed.
        _fail(f"invalid JSON in {label} at line {exc.lineno}, column {exc.colno}")


def _require_object(value: Any, label: str) -> dict:
    if not isinstance(value, dict):
        _fail(f"{label} must be a JSON object")
    return value


def _require_array(value: Any, label: str) -> list:
    if not isinstance(value, list):
        _fail(f"{label} must be a JSON array")
    return value


def _require_string(value: Any, label: str, *, allow_empty: bool = False) -> str:
    if not isinstance(value, str):
        _fail(f"{label} must be a string")
    if not allow_empty and not value:
        _fail(f"{label} must not be empty")
    return value


def _require_bool(value: Any, label: str) -> bool:
    # ``type(...) is bool`` rejects 0/1, which json would otherwise accept.
    if type(value) is not bool:
        _fail(f"{label} must be a boolean")
    return value


def _require_string_array(value: Any, label: str) -> tuple[str, ...]:
    items = _require_array(value, label)
    return tuple(
        _require_string(item, f"{label}[{index}]")
        for index, item in enumerate(items)
    )


def _parse_tokens(document: Any) -> tuple[Token, ...]:
    root = _require_object(document, "inventory.json")
    version = root.get("schema_version")
    if type(version) is not int or version != 1:
        _fail("inventory.json schema_version must be 1")

    raw_tokens = _require_array(root.get("tokens"), "inventory.json tokens")
    tokens: list[Token] = []
    seen_ids: dict[str, bool] = {}
    seen_values: dict[str, str] = {}

    for index, raw in enumerate(raw_tokens):
        item = _require_object(raw, f"inventory.json tokens[{index}]")
        token_id = _require_string(item.get("token_id"), f"tokens[{index}].token_id")
        value = _require_string(item.get("value"), f"tokens[{index}].value")
        state = _require_string(item.get("state"), f"tokens[{index}].state")

        if state not in TOKEN_STATES:
            _fail(f"tokens[{index}].state must be one of {list(TOKEN_STATES)}")
        if "\n" in value or "\r" in value:
            _fail(f"tokens[{index}].value must be a single line")
        if token_id in seen_ids:
            _fail(f"duplicate token_id {token_id!r} at tokens[{index}]")
        if value in seen_values:
            # Do not print the duplicated value itself.
            _fail(
                "duplicate token value shared by "
                f"{seen_values[value]!r} and {token_id!r}"
            )

        seen_ids[token_id] = True
        seen_values[value] = token_id
        tokens.append(Token(token_id=token_id, value=value, state=state))

    return tuple(tokens)


def _parse_workflows(document: Any) -> tuple[Workflow, ...]:
    root = _require_object(document, "ci.json")
    if "schema_version" in root:
        version = root["schema_version"]
        if type(version) is not int or version != 1:
            _fail("ci.json schema_version must be 1 if present")

    raw_workflows = _require_array(root.get("workflows"), "ci.json workflows")
    workflows: list[Workflow] = []
    seen_ids: set[str] = set()

    for index, raw in enumerate(raw_workflows):
        item = _require_object(raw, f"ci.json workflows[{index}]")
        workflow_id = _require_string(
            item.get("workflow_id"), f"workflows[{index}].workflow_id"
        )
        if workflow_id in seen_ids:
            _fail(f"duplicate workflow_id {workflow_id!r}")
        seen_ids.add(workflow_id)

        trigger = _require_string(
            item.get("trigger"), f"workflows[{index}].trigger"
        )
        if trigger not in TRIGGERS:
            _fail(f"workflows[{index}].trigger must be one of {list(TRIGGERS)}")

        permissions = _require_string(
            item.get("permissions"), f"workflows[{index}].permissions"
        )
        if permissions not in PERMISSIONS:
            _fail(
                f"workflows[{index}].permissions must be one of "
                f"{list(PERMISSIONS)}"
            )

        workflows.append(
            Workflow(
                workflow_id=workflow_id,
                trigger=trigger,
                runs_untrusted_code=_require_bool(
                    item.get("runs_untrusted_code"),
                    f"workflows[{index}].runs_untrusted_code",
                ),
                secret_refs=_require_string_array(
                    item.get("secret_refs"), f"workflows[{index}].secret_refs"
                ),
                permissions=permissions,
                log_environment=_require_bool(
                    item.get("log_environment"),
                    f"workflows[{index}].log_environment",
                ),
                artifact_paths=_require_string_array(
                    item.get("artifact_paths"),
                    f"workflows[{index}].artifact_paths",
                ),
            )
        )

    return tuple(workflows)


def load_snapshot(snapshot_dir: str | Path) -> Snapshot:
    """Load and validate one snapshot directory.

    Raises:
        SchemaError: for missing files, malformed JSON or schema violations.
    """
    root = Path(snapshot_dir)
    if not root.is_dir():
        _fail(f"snapshot directory not found: {root}")

    inventory = _read_json(root / "inventory.json", "inventory.json")
    ci = _read_json(root / "ci.json", "ci.json")

    tokens = _parse_tokens(inventory)
    workflows = _parse_workflows(ci)

    return Snapshot(
        root=root,
        name=root.name or "snapshot",
        tokens=tokens,
        workflows=workflows,
        token_by_id={token.token_id: token for token in tokens},
    )
