#!/usr/bin/env python3
"""Reproduce the audit and emit captured verification evidence.

Run from the repository root:

    python3 tools/verify.py > outputs/verification.txt

The script is deterministic (no timestamps) and exits nonzero if any check
fails.  It never prints a raw inventory token value.
"""

from __future__ import annotations

import hashlib
import json
import platform
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
SNAPSHOTS = (
    ("snapshot-one", REPO_ROOT / "inputs" / "snapshot-one"),
    ("snapshot-two", REPO_ROOT / "inputs" / "snapshot-two"),
)
OUTPUTS = REPO_ROOT / "outputs"
EXPECTED_COUNTS = {
    "snapshot-one": (5, 3, 0),
    "snapshot-two": (2, 4, 0),
}
DOC_FILES = (
    REPO_ROOT / "README.md",
    REPO_ROOT / "SUBMISSION.md",
    REPO_ROOT / "WALKTHROUGH.md",
    REPO_ROOT / "WORKLOG.md",
    REPO_ROOT / "AI_USE.md",
)

_checks: list[tuple[str, bool, str]] = []


def check(name: str, passed: bool, detail: str = "") -> None:
    _checks.append((name, passed, detail))
    suffix = f": {detail}" if detail else ""
    print(f"[{'PASS' if passed else 'FAIL'}] {name}{suffix}")


def run(command: list[str], cwd: Path = REPO_ROOT) -> subprocess.CompletedProcess:
    return subprocess.run(command, cwd=cwd, capture_output=True, text=True)


def tree_hashes(root: Path) -> dict[str, str]:
    hashes = {}
    for path in sorted(root.rglob("*")):
        if path.is_file():
            hashes[path.relative_to(root).as_posix()] = hashlib.sha256(
                path.read_bytes()
            ).hexdigest()
    return hashes


def file_hash(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def leak_scan() -> None:
    values: list[tuple[str, str]] = []
    for name, snapshot in SNAPSHOTS:
        data = json.loads((snapshot / "inventory.json").read_text(encoding="utf-8"))
        for item in data["tokens"]:
            values.append((item["token_id"], item["value"]))

    files: list[Path] = []
    if OUTPUTS.is_dir():
        files.extend(
            path
            for path in OUTPUTS.rglob("*")
            if path.is_file() and path.name != "verification.txt"
        )
    files.extend(path for path in DOC_FILES if path.is_file())
    for directory in ("auditor", "tests", "tools"):
        base = REPO_ROOT / directory
        if base.is_dir():
            files.extend(path for path in base.rglob("*.py") if path.is_file())

    leaks: list[tuple[str, str]] = []
    for path in sorted(set(files)):
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        for token_id, value in values:
            if value and value in text:
                leaks.append((token_id, path.relative_to(REPO_ROOT).as_posix()))

    if leaks:
        for token_id, path in leaks:
            print(f"  leak: token_id={token_id} found in {path}")
    check(
        "no raw inventory values in outputs, docs or source",
        not leaks,
        f"{len(files)} files scanned",
    )


def main() -> int:
    OUTPUTS.mkdir(parents=True, exist_ok=True)
    print("PineBuild audit verification")
    print("$ python3 --version")
    print(f"Python {sys.version.split()[0]}")
    print(f"Platform: {platform.platform()}")
    print()

    tests = run(
        [
            sys.executable,
            "-m",
            "unittest",
            "discover",
            "-s",
            "tests",
            "-t",
            ".",
            "-v",
        ]
    )
    print("$ python3 -m unittest discover -s tests -t . -v")
    print((tests.stdout + tests.stderr).rstrip())
    print()
    check("unit test suite", tests.returncode == 0)

    for name, snapshot in SNAPSHOTS:
        out = OUTPUTS / name
        before = tree_hashes(snapshot)
        command = [
            sys.executable,
            "-m",
            "auditor",
            snapshot.relative_to(REPO_ROOT).as_posix(),
            "--out",
            out.relative_to(REPO_ROOT).as_posix(),
        ]
        result = run(command)
        print(f"$ {' '.join(command)}")
        print(f"exit={result.returncode}")
        print(result.stdout.rstrip())
        if result.stderr.strip():
            print(result.stderr.rstrip())
        print()

        check(f"{name}: audit exits 0", result.returncode == 0)
        check(
            f"{name}: snapshot files unchanged",
            before == tree_hashes(snapshot),
            f"{len(before)} files hashed",
        )

        if (out / "findings.json").is_file():
            report = json.loads(
                (out / "findings.json").read_text(encoding="utf-8")
            )
            actual = (
                report["counts"]["findings"],
                report["counts"]["benign"],
                report["counts"]["unresolved"],
            )
            expected = EXPECTED_COUNTS[name]
            check(
                f"{name}: expected counts (findings, benign, unresolved)",
                actual == expected,
                f"{actual} == {expected}",
            )
        else:
            check(f"{name}: findings.json exists", False)

        with tempfile.TemporaryDirectory() as temporary:
            rerun_out = Path(temporary) / "rerun"
            rerun = run(
                [
                    sys.executable,
                    "-m",
                    "auditor",
                    str(snapshot),
                    "--out",
                    str(rerun_out),
                ]
            )
            identical = (
                rerun.returncode == 0
                and (rerun_out / "findings.json").read_bytes()
                == (out / "findings.json").read_bytes()
                and (rerun_out / "summary.txt").read_bytes()
                == (out / "summary.txt").read_bytes()
            )
            check(f"{name}: rerun is byte-identical", identical)

    # A fresh copy of the source and inputs must reproduce the submitted
    # outputs byte-for-byte, proving there is no hidden state or absolute-path
    # dependency.
    with tempfile.TemporaryDirectory() as temporary:
        fresh = Path(temporary) / "fresh-copy"
        shutil.copytree(
            REPO_ROOT,
            fresh,
            ignore=shutil.ignore_patterns("__pycache__", "*.pyc", ".git", "outputs"),
        )
        fresh_ok = True
        for name, _ in SNAPSHOTS:
            result = run(
                [
                    sys.executable,
                    "-m",
                    "auditor",
                    f"inputs/{name}",
                    "--out",
                    f"outputs/{name}",
                ],
                cwd=fresh,
            )
            if result.returncode != 0:
                fresh_ok = False
                continue
            for filename in ("findings.json", "summary.txt"):
                expected = (REPO_ROOT / "outputs" / name / filename).read_bytes()
                actual = (fresh / "outputs" / name / filename).read_bytes()
                if actual != expected:
                    fresh_ok = False
        fresh_tests = run(
            [
                sys.executable,
                "-m",
                "unittest",
                "discover",
                "-s",
                "tests",
                "-t",
                ".",
            ],
            cwd=fresh,
        )
        check(
            "fresh copy reproduces outputs and passes tests",
            fresh_ok and fresh_tests.returncode == 0,
        )

    diff_command = [
        sys.executable,
        "tools/compare_outputs.py",
        "outputs/snapshot-one/findings.json",
        "outputs/snapshot-two/findings.json",
    ]
    diff = run(diff_command)
    if diff.returncode == 0:
        (OUTPUTS / "snapshot-diff.txt").write_text(
            diff.stdout, encoding="utf-8", newline="\n"
        )
    print(f"$ {' '.join(diff_command)}")
    print(diff.stdout.rstrip())
    print()
    check("snapshot comparison", diff.returncode == 0)

    print("OUTPUT SHA-256")
    for relative in (
        "outputs/snapshot-one/findings.json",
        "outputs/snapshot-one/summary.txt",
        "outputs/snapshot-two/findings.json",
        "outputs/snapshot-two/summary.txt",
        "outputs/snapshot-diff.txt",
    ):
        path = REPO_ROOT / relative
        if path.is_file():
            print(f"  {relative}  {file_hash(path)}")
    print()

    leak_scan()
    print()

    passed = sum(1 for _, ok, _ in _checks if ok)
    total = len(_checks)
    print(f"RESULT: {passed}/{total} checks passed")
    return 0 if passed == total else 1


if __name__ == "__main__":
    raise SystemExit(main())
