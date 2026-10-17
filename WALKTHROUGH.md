# Five-minute text walkthrough

## 0:00 — What this is

An offline, deterministic auditor for the two PineBuild snapshots. It implements
S1-S5 from `inputs/policy.md`, keeps CI references separate from token text
matches, redacts values at the scanner boundary, and emits a machine-readable
report plus a readable summary. Nothing is executed and no raw `DEMO_*` value is
printed.

## 0:30 — Reproduce

From the repository root:

```bash
python3 -m auditor inputs/snapshot-one --out outputs/snapshot-one
python3 -m auditor inputs/snapshot-two --out outputs/snapshot-two
python3 -m unittest discover -s tests -t . -v
python3 tools/verify.py > outputs/verification.txt
```

The audit commands exit `0` on a completed audit. `outputs/verification.txt`
captures Python/platform versions, the 74-test result, exit codes, a byte-for-byte
rerun comparison, source-integrity hashes and a leak scan.

## 1:00 — Snapshot one

Five risk findings and three benign decisions:

- `S1 app/env.txt:2` (`release-active`) — active plaintext, even though the
  value also appears in an environment export. Redacted evidence is
  `RELEASE_TOKEN=[REDACTED:release-active]`.
- `S2 pr-build` — `runs_untrusted_code=true` with the active secret ref.
- `S3 pr-build` — `permissions=write-all`, which is never allowed.
- `S4 pr-build` — `log_environment=true` with the active secret ref.
- `S5 pr-build` — artifact `app/env.txt` is a configured sensitive path.

Benign: `tests/mock.txt:2` is `test_only`, `docs/rotation.txt:1` is
`revoked_in_fixture`, and `release` passes S2-S5 (`tag` + trusted +
`release-write`, no logging, no sensitive artifact). The filename is never the
reason for suppression.

## 2:15 — Snapshot two

Two risk findings and four benign decisions:

- `S1 docs/rotation.txt:2` (`release-rotated`) — the newly rotated active
  token was left as a "temporary troubleshooting copy." The filename is not an
  exemption.
- `S5 pr-build` — `app/*` matches the configured sensitive path
  `app/env.txt`.

`app/env.txt:2` is now benign because its value is revoked in inventory.
`tests/mock.txt:2` stays benign as `test_only`; `docs/rotation.txt:1` now
references the revoked old credential. `release` remains correctly configured.

This is the assumption the second snapshot breaks: **rotation did not remove
the exposure; it moved it.** The CI behaviour improved (S2-S4 are gone), but
the active value is now in `docs/`, and the artifact wildcard still publishes
the sensitive env path (currently holding a revoked marker, but protected by
policy for future credentials).

## 3:30 — Prioritization

The team can immediately change one workflow and schedule one cleanup. Ranking
rule: cut a live path for an **active** credential first, then remove plaintext
copies and add defense-in-depth.

Snapshot one:

1. Change `pr-build` now: remove the active ref, use `read-only`, disable
   logging, stop publishing `app/env.txt`. One edit clears S2-S5.
2. Schedule cleanup: remove and rotate the plaintext copy in `app/env.txt`.
   Keep the credential available to the trusted `release` job.

Snapshot two:

1. Schedule cleanup: remove the active `release-rotated` copy from
   `docs/rotation.txt` and rotate/update the release credential.
2. Change `pr-build`: replace `app/*` with explicit non-sensitive artifact
   paths. This is future-credential protection; today the matched file holds a
   revoked marker.

The generated diff in `outputs/snapshot-diff.txt` states this mechanically:
four findings resolved, one introduced (`S1 docs/rotation.txt:2`), one
unchanged (`S5 pr-build`).

## 4:30 — Design notes and limits

- S1 uses exact inventory-value matching, longest value first, with
  non-overlapping spans. Inventory and `ci.json` are never text-scanned.
- S2/S4 resolve `secret_refs` through inventory; only `active_in_fixture`
  counts. Unknown refs become `CONFIG-UNRESOLVED`, never invented credentials.
- S3 is exact: `read-only` always; `release-write` only for `tag` with
  `runs_untrusted_code=false`; `write-all` never.
- S5 uses `fnmatchcase` over supplied content paths intersected with the two
  configured sensitive paths. No glob/filesystem expansion. Note that
  `fnmatch` lets `*` cross `/`, so `app/*` matches `app/env.txt`.
- Outputs are deterministic: relative POSIX paths, sorted decisions, sorted
  JSON keys, no timestamps, no absolute snapshot paths. The rerun check is
  byte-identical.
- Limits: this is not a general secret scanner, does not inspect git history,
  does not decode binaries, and the sensitive-path list is fixed by policy.
