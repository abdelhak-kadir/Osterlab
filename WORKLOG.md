# Decision and work log

## Scope

Built an offline, read-only auditor for the two supplied snapshots, with a
reusable CLI, deterministic outputs, a 74-test suite, captured verification and
a prioritized remediation queue. The original brief remains in `README.md`.

## Decisions

1. **One pure function per rule.** S1 lives in `scanner.py`; S2-S5 and unknown
   reference handling live in `rules.py`. Each can be tested without the CLI.
2. **State-based suppression, never filename-based.** `active_in_fixture` is a
   finding; `revoked_in_fixture` and `test_only` are explicit benign decisions.
   `tests/` and `docs/` are still scanned: snapshot two's active token is in
   `docs/rotation.txt`.
3. **CI references are separate from text matches.** S2/S4 resolve `secret_refs`
   by `token_id`; S1 scans literal values. An unknown ref is
   `CONFIG-UNRESOLVED`, never an invented credential and never active.
4. **S5 is a pure string match.** Patterns are applied with
   `fnmatch.fnmatchcase` to supplied content paths that are also configured
   sensitive paths. No glob, filesystem expansion or network expansion. Token
   state is ignored, which is why a revoked marker still triggers S5.
5. **Redact at the scanner boundary.** `Finding.evidence` is constructed from
   `redact_text(...)`; raw values do not enter the report model. Markers retain
   `token_id` for traceability.
6. **Split risk findings from benign decisions.** `findings.json` has separate
   `findings` and `benign_decisions` arrays plus explicit counts. A single
   mixed array made "5 findings" ambiguous because it contained 8 entries.
7. **Deterministic output.** Relative POSIX paths, sorted decisions, sorted JSON
   keys, `\n` newlines, no timestamps and no absolute snapshot path. A rerun is
   byte-identical.
8. **Exit codes.** A completed audit exits `0` even with findings; schema/input
   errors exit `2`; `--fail-on-findings` exits `1`. This keeps the documented
   commands successful while supporting CI gating.

## Prioritization

Ranking rule: **cut a live path through which an active credential can leave
the system first; then remove plaintext copies and apply defense-in-depth.**
The capacity levers are exactly one immediate workflow change and one scheduled
repository cleanup.

### Snapshot one

1. **Change `pr-build`** (immediate workflow lever). Remove the active secret
   ref, set `read-only`, disable `log_environment`, and stop publishing
   `app/env.txt`. One edit clears S2, S3, S4 and S5. This is first because the
   workflow is a live CI path to an active credential.
2. **Schedule repository cleanup** (cleanup lever). Remove the plaintext
   `release-active` value from `app/env.txt` and rotate it, updating the trusted
   release secret store. The workflow edit does not remove the plaintext copy.

### Snapshot two

1. **Schedule repository cleanup** (cleanup lever). Remove the active
   `release-rotated` value from `docs/rotation.txt`; rotate/update the
   credential used by the trusted `release` workflow. This is the only active
   plaintext exposure.
2. **Change `pr-build`** (workflow lever). Replace `app/*` with explicit
   non-sensitive artifact paths. This is second because the matched file
   currently holds a revoked marker: S5 is protecting future credentials, not
   an active token.

### What changed between snapshots

- Resolved: S1 at `app/env.txt:2` (its value is now revoked) and S2/S3/S4 on
  `pr-build` (refs emptied, `read-only`, logging off).
- Introduced: S1 at `docs/rotation.txt:2` (`release-rotated`). Rotation moved
  the credential into a troubleshooting note instead of removing the plaintext.
- Unchanged: S5 on `pr-build`, but mutated from explicit `app/env.txt` to the
  `app/*` wildcard. It still matches the configured sensitive path.
- `release` remains compliant in both snapshots. Cleanup must not break it:
  it legitimately uses the active credential through the secret store.

## Obstacle and response

**Obstacle:** S5 could have been implemented two conflicting ways: match the
configured sensitive paths whether or not they exist, or expand artifact
patterns against the filesystem. Both conflict with the policy sentence
"Match only supplied content file paths, no network expansion."

**Response:** Intersect the configured sensitive list with the actual supplied
content files, then apply pure `fnmatchcase` string matching. Added
`test_s5_does_not_fire_when_sensitive_file_is_absent`, the case-sensitivity
test, and the whole-path test. This keeps the result reproducible and avoids
touching anything outside the snapshot.

A second judgment call: unknown refs. They are configuration evidence
(`CONFIG-UNRESOLVED`, medium severity), not active secrets. Tests assert they
never fire S2/S4 and that mixed active/revoked/unknown refs report only the
active ref in S2 evidence.

## Validation and refinement

**Refinement (from plan review to implementation):** the first plan used one
mixed decisions array and exited `1` whenever findings existed. The acceptance
text asks for a finding list plus evidence for benign decisions, and the
reproducible-command requirement makes a "successful" command exiting `1`
confusing. Refined to two arrays with explicit counts, exit `0` on a completed
audit, and an opt-in `--fail-on-findings`. Covered by the golden count
assertions and `tests/test_cli.py`.

**Validation:** the S3 table test exercises all 12 combinations of trigger
(`pull_request`/`tag`), `runs_untrusted_code` (true/false) and permissions
(`read-only`/`release-write`/`write-all`), asserting the exact allowed decision
rather than only checking that a message exists. The full suite (74 tests) and
`tools/verify.py` pass, including a byte-identical rerun and source-integrity
hashes.

## Limits

- Only inventory-classified values are detected; this is not a general secret
  scanner and does not inspect git history.
- Text is read as UTF-8 with replacement; binaries are not decoded or specially
  parsed. Symlinked content is skipped.
- The sensitive-path list is fixed by the policy (`app/env.txt`,
  `docs/rotation.txt`); a new policy-sensitive path requires a constant update.
- No real CI pipeline is executed, no service is contacted, and no real secret
  is rotated. All fixtures are nonfunctional training markers.
- Unknown `secret_refs` stay unresolved by design.

## Next step

If this became an operational tool, the next step would be to move the
sensitive-path list and rule thresholds into a machine-readable policy file,
add git-history scanning for rotated values, and run the auditor in CI with
`--fail-on-findings` while publishing `findings.json` as the review artifact.
