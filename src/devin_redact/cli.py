"""Thin CLI wrapper — all logic lives in the library modules."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from . import __version__, engine


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="devin-redact",
        description="Secret and PII redaction that understands Devin tool-call "
        "semantics (unofficial).",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    def _add_target_args(p: argparse.ArgumentParser) -> None:
        p.add_argument("paths", nargs="+", type=Path, help="files or directories to inspect")
        p.add_argument("--report", type=Path, default=None, help="also write the JSON report to this file")

    _add_target_args(sub.add_parser("scan", help="read-only scan, prints a JSON report"))
    redact_p = sub.add_parser("redact", help="redact findings (dry-run only in M1)")
    _add_target_args(redact_p)
    redact_p.add_argument(
        "--apply",
        action="store_true",
        help="actually redact in place (NOT implemented until M2)",
    )
    _add_target_args(sub.add_parser("verify", help="exit non-zero when publication is blocked (M2)"))
    return parser


def _emit(report: dict, report_path: Path | None) -> None:
    blob = json.dumps(report, indent=2, sort_keys=True, ensure_ascii=True)
    print(blob)
    if report_path is not None:
        report_path.write_text(blob + "\n", encoding="utf-8")


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)

    if args.command == "scan":
        _emit(engine.scan(args.paths), args.report)
        return 0

    if args.command == "redact":
        if args.apply:
            print(
                "devin-redact: --apply is not implemented in M1 "
                "(in-place SQLite redaction ships in M2)",
                file=sys.stderr,
            )
            return 3
        _emit(engine.redact(args.paths), args.report)
        return 0

    if args.command == "verify":
        print("devin-redact: verify is not implemented yet (planned for M2)", file=sys.stderr)
        return 3

    return 2


if __name__ == "__main__":
    raise SystemExit(main())
