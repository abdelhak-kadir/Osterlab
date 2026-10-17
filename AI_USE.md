# AI use note

**Tool:** Claude Code (Anthropic's agentic coding CLI), used in this working
session for implementation, tests, verification and drafting. No AI-generated
claim below is presented as an AI failure; each entry records something that
was actually changed or rejected during this session.

## Accepted

The proposed decomposition of the audit into pure rule functions (S1 in the
scanner, S2-S5 in the rules module) with state-based suppression and a
deterministic report was accepted.

**How it was checked:** `python3 -m unittest discover -s tests -t . -v` runs 74
tests, including exact golden expectations for both snapshots
(`tests/test_golden.py`) and a 12-case permission/trigger table
(`tests/test_rules.py::test_s3_permission_trigger_table`). The
`test_revoked_and_test_only_are_benign` and
`test_filename_does_not_exempt_active_token` tests specifically check the
state-versus-filename distinction.

## Corrected

The initial build plan placed risk findings and benign decisions in one array
with a `decision` field and exited `1` whenever findings existed. That made the
finding count ambiguous (the snapshot-one array would contain 8 entries for 5
risk findings) and made the documented audit commands look failed.

**Correction:** separate `findings` and `benign_decisions` arrays with explicit
counts, exit `0` on a completed audit, and add `--fail-on-findings` for CI use.

**How it was checked:** golden tests assert exact decision keys and counts;
`tests/test_cli.py` asserts exit codes `0`, `1` (opt-in) and `2` (schema/input),
and verifies both output files are still written when `--fail-on-findings`
returns `1`.

## Rejected

The initial plan listed the observation that `fnmatch`'s `*` crosses `/` (so
`app/*` matches `app/env.txt`) as a candidate for the "validation/refinement"
entry. That behavior is a policy assumption, not a refinement, and presenting
it as the refinement would misreport the work.

**Rejection and replacement:** documented the behavior as an assumption/limit
and added tests for it (`test_s5_wildcard_matches_sensitive_path`,
`test_s5_star_matches_both_sensitive_paths`,
`test_s5_aggregates_multiple_patterns_in_one_finding`). The work log instead
records a real refinement (split output schema plus exit-code change) and a
real validation (the 12-case S3 table and byte-identical rerun).

## Verification performed

- `python3 -m unittest discover -s tests -t . -v` — 74 tests, all passing.
- `python3 tools/verify.py > outputs/verification.txt` — versions, commands,
  exit codes, expected counts, byte-identical rerun, source hashes and a leak
  scan.
- Leak scan: no raw inventory value appears in `outputs/`, the submission docs,
  the auditor source or the tests; test fixtures use unrelated synthetic values.
- Source integrity: snapshot file hashes are unchanged before and after each
  audit.
