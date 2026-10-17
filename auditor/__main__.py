"""Command-line entry point: python3 -m auditor <snapshot> --out <dir>."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from . import __version__
from .api import audit_snapshot, write_outputs
from .loader import SchemaError


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python3 -m auditor",
        description=(
            "Offline PineBuild secrets/CI auditor. Read-only and network-free. "
            "A successful audit exits 0 even when risk findings exist."
        ),
    )
    parser.add_argument(
        "snapshot_dir",
        type=Path,
        help="snapshot directory containing inventory.json and ci.json",
    )
    parser.add_argument(
        "--out",
        type=Path,
        required=True,
        help="directory to receive findings.json and summary.txt",
    )
    parser.add_argument(
        "--fail-on-findings",
        action="store_true",
        help="exit 1 when at least one risk finding is present (CI-style use)",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"pinebuild-auditor {__version__}",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)

    snapshot = args.snapshot_dir.resolve()
    out = args.out.resolve()

    if not snapshot.is_dir():
        print(
            f"error: snapshot directory not found: {args.snapshot_dir}",
            file=sys.stderr,
        )
        return 2
    if out == snapshot or snapshot in out.parents:
        print(
            "error: --out must not be inside the snapshot directory "
            "(a rerun would scan its own output)",
            file=sys.stderr,
        )
        return 2

    try:
        report, summary = audit_snapshot(snapshot)
        write_outputs(report, summary, out)
    except SchemaError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    except OSError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    # Readable summary on stdout; the same text is written to summary.txt.
    sys.stdout.write(summary)

    if args.fail_on_findings and report["counts"]["findings"] > 0:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
