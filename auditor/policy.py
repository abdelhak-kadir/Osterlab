"""Policy constants for the fictional PineBuild audit.

These values are fixed by ``inputs/policy.md``.  Keeping them in one module
means the rule functions stay free of policy literals and are easy to test.
"""

# The policy version is written into the machine-readable report so a reviewer
# can tell which rule set produced a result.
POLICY_VERSION = "pinebuild-policy-v1"

# Only these directories are text-scanned.  inventory.json and ci.json are
# classification/configuration metadata, not leaked content.
SCANNED_DIRS = ("app", "tests", "docs", "build")

# S5: configured sensitive paths.  These are matched with fnmatch-style
# whole-relative-path matching against files actually supplied in the snapshot.
SENSITIVE_PATHS = ("app/env.txt", "docs/rotation.txt")

# Explicitly excluded from the text scan, for documentation and tests.
NOT_SCANNED = ("inventory.json", "ci.json")
