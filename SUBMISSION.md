# PineBuild secrets & CI audit — submission

The original exercise brief is preserved unchanged in [`README.md`](README.md).
This file is the entry point for the completed submission.

## Requirements and scope

- Python 3.10+ (verified with Python 3.14.4), standard library only.
- Offline and read-only: no network, no package installs, no CI execution, no
  real credential rotation.
- Every `DEMO_*` marker in `inputs/` is a nonfunctional training value.
- The auditor reads `inventory.json`, `ci.json` and the four content
  directories (`app/`, `tests/`, `docs/`, `build/`). It never modifies the
  snapshot.

## Exact commands (run from the repository root)

```bash
python3 -m auditor inputs/snapshot-one --out outputs/snapshot-one
python3 -m auditor inputs/snapshot-two --out outputs/snapshot-two
python3 -m unittest discover -s tests -t . -v
python3 tools/verify.py > outputs/verification.txt
```

Each audit writes `findings.json` (machine-readable) and `summary.txt`
(readable) and prints the summary to stdout.

Exit codes: `0` = audit completed (even with findings); `2` = input or schema
error; with `--fail-on-findings`, `1` = at least one risk finding. This keeps
the documented commands successful while still supporting CI-style gating.

To compare the two snapshots:

```bash
python3 tools/compare_outputs.py \
  outputs/snapshot-one/findings.json \
  outputs/snapshot-two/findings.json
```

## Results

| Snapshot | Risk findings | Benign decisions | Unresolved refs |
|---|---:|---:|---:|
| one | 5 | 3 | 0 |
| two | 2 | 4 | 0 |

Snapshot one: S1 at `app/env.txt:2` (`release-active`), and `pr-build`
violates S2, S3, S4 and S5. The `release` workflow is correctly configured.

Snapshot two: S1 at `docs/rotation.txt:2` (`release-rotated`), and `pr-build`
violates S5 because `app/*` matches the configured sensitive path
`app/env.txt`. `app/env.txt` now holds a revoked marker, so its S1 is benign;
the active credential moved into the rotation note instead.

`WORKFLOW` entries in `benign_decisions` are composite evidence that a workflow
passes S2-S5; they are not a separate policy rule. `CONFIG-UNRESOLVED` is the
only non-S rule, and it appears in `findings` only when a `secret_ref` cannot be
resolved.

## Remediation queue

Ranking rule: cut a live path through which an **active** credential can leave
the system first; then remove plaintext copies and apply defense-in-depth. The
team has exactly two levers: one immediate workflow change and one scheduled
repository cleanup.

**Snapshot one**

1. **Change `pr-build` now** (workflow lever). Remove the active secret
   reference, set `permissions: read-only`, disable `log_environment`, and stop
   publishing `app/env.txt` (publish only explicit non-sensitive files). One
   edit clears S2, S3, S4 and S5.
2. **Schedule repository cleanup** (cleanup lever). Remove the plaintext
   `release-active` value from `app/env.txt` and rotate it. Keep the credential
   available to the trusted `release` workflow through the secret store; the
   workflow edit does not remove the plaintext copy, so this step is mandatory.

**Snapshot two**

1. **Schedule repository cleanup** (cleanup lever). Remove the active
   `release-rotated` value from `docs/rotation.txt`; rotate/update the
   credential used by the trusted `release` workflow. This is the only active
   plaintext exposure.
2. **Change `pr-build`** (workflow lever). Replace `app/*` with explicit
   non-sensitive artifact paths. The wildcard currently publishes a file that
   contains only a revoked marker, so this is future-credential protection
   rather than a current active-secret leak.

The full change explanation is in [`WORKLOG.md`](WORKLOG.md) and the generated
[`outputs/snapshot-diff.txt`](outputs/snapshot-diff.txt).

## How to audit new same-schema content

1. Create a directory with `inventory.json`, `ci.json`, and any of
   `app/`, `tests/`, `docs/`, `build/`.
2. Run:

   ```bash
   python3 -m auditor path/to/new-snapshot --out outputs/new-snapshot
   ```

3. Read `findings.json` or `summary.txt`. Unknown `secret_refs` become
   `CONFIG-UNRESOLVED` findings; they are never treated as active credentials.
   Extra JSON fields are tolerated, so same-schema additions do not require
   code changes.

`tests/test_golden.py::test_third_synthetic_mutation_needs_no_code_change`
demonstrates this with a synthetic snapshot.

## Artifact map

- `auditor/` — loader, S1 scanner, S2-S5 rules, redaction, deterministic report,
  CLI.
- `tests/` — 74 tests: unit, schema, redaction, CLI, golden and synthetic
  mutation coverage.
- `outputs/snapshot-one/`, `outputs/snapshot-two/` — captured results.
- `outputs/verification.txt` — versions, commands, exit codes, test output,
  determinism rerun, source-integrity hashes, leak scan.
- `outputs/snapshot-diff.txt` — machine-generated change summary.
- [`WALKTHROUGH.md`](WALKTHROUGH.md) — five-minute text walkthrough.
- [`WORKLOG.md`](WORKLOG.md) — decisions, prioritization, obstacle,
  refinement, limits and next step.
- [`AI_USE.md`](AI_USE.md) — accepted/corrected/rejected AI output and checks.
