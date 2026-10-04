"""Thin CLI wrapper — all logic lives in the library modules."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from . import __version__, engine
from .sarif import report_to_sarif


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

    scan_p = sub.add_parser("scan", help="read-only scan, prints a JSON report")
    _add_target_args(scan_p)
    scan_p.add_argument(
        "--format",
        choices=("json", "sarif"),
        default="json",
        help="output format (sarif = SARIF 2.1.0 for CI/code-scanning ingestion)",
    )

    redact_p = sub.add_parser("redact", help="redact findings (dry-run by default)")
    _add_target_args(redact_p)
    redact_p.add_argument("--apply", action="store_true", help="actually write redactions")
    redact_p.add_argument(
        "--i-know-this-is-irreversible",
        action="store_true",
        help="required with --apply (long flag, on purpose)",
    )

    verify_p = sub.add_parser("verify", help="publication gate — non-zero exit unless CLEAN")
    verify_p.add_argument("paths", nargs="+", type=Path, help="files or directories to verify")
    verify_p.add_argument("--json", action="store_true", help="print the full JSON report")
    return parser


def _emit(report: dict, report_path: Path | None) -> None:
    blob = json.dumps(report, indent=2, sort_keys=True, ensure_ascii=True)
    print(blob)
    if report_path is not None:
        report_path.write_text(blob + "\n", encoding="utf-8")


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)

    if args.command == "scan":
        report = engine.scan(args.paths)
        _emit(report_to_sarif(report) if args.format == "sarif" else report, args.report)
        return 0

    if args.command == "redact":
        if args.apply and not args.i_know_this_is_irreversible:
            print(
                "devin-redact: --apply requires --i-know-this-is-irreversible",
                file=sys.stderr,
            )
            return 3
        try:
            result = engine.redact(
                args.paths,
                apply=args.apply,
                confirm_irreversible=args.i_know_this_is_irreversible,
            )
        except RuntimeError as exc:
            print(f"devin-redact: {exc}", file=sys.stderr)
            return 3
        _emit(result, args.report)
        return 0 if result.get("applied_ok", True) else 1

    if args.command == "verify":
        report = engine.scan(args.paths)
        if args.json:
            _emit(report, None)
        else:
            print(f"PUBLICATION STATUS: {report['publication_status']}")
            print(
                f"{report['files_scanned']} file(s) scanned, "
                f"{report['findings_total']} finding(s) "
                f"({report['secrets']} secret-class)"
            )
            for cat, n in report["by_category"].items():
                print(f"  {cat}: {n}")
        return 0 if report["publication_status"] == "CLEAN" else 1

    return 2


if __name__ == "__main__":
    raise SystemExit(main())
