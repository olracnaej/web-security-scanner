"""Command line interface."""

from __future__ import annotations

import argparse
import sys
from collections import Counter

from scanner import __version__
from scanner.engine import ScanResult, run_scan
from scanner.http import FetchError
from scanner.models import Severity
from scanner.safety import RefusedTarget

EXIT_OK = 0
EXIT_FINDINGS = 1  # only with --fail-on
EXIT_REFUSED = 2
EXIT_FETCH_ERROR = 3


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="webscan",
        description="Check a website for common security hygiene problems. "
        "Only scan sites you own or have written permission to test.",
    )
    parser.add_argument("--version", action="version", version=__version__)
    sub = parser.add_subparsers(dest="command", required=True)

    scan = sub.add_parser("scan", help="scan a URL")
    scan.add_argument("url", help="e.g. http://127.0.0.1:8001")
    scan.add_argument(
        "--allow-host", action="append", default=[], metavar="HOST",
        help="exact host name you have permission to scan (repeatable). "
        "Not needed for localhost.",
    )
    scan.add_argument(
        "--fail-on", choices=["low", "medium", "high"],
        help="exit with code 1 if any finding is at least this severe (for CI)",
    )
    return parser


def print_result(result: ScanResult) -> None:
    resp = result.response
    print(f"Target: {resp.target.url}  (HTTP {resp.status})")
    if resp.redirects:
        print(f"Redirects followed: {len(resp.redirects)}")
    if resp.tls_verified is False:
        print("Note: the TLS certificate did not verify (details in the TLS check, next step).")

    counts = Counter(f.severity for f in result.findings)
    summary = ", ".join(
        f"{counts[s]} {s.label}" for s in sorted(Severity, reverse=True) if counts[s]
    )
    print(f"Findings: {summary or 'none'}\n")

    for f in result.findings:
        print(f"[{f.severity.label.upper()}] {f.title}  ({f.check_id})")
        print(f"  Why:   {f.description}")
        print(f"  Fix:   {f.recommendation}")
        if f.evidence:
            print(f"  Found: {f.evidence}")
        print()


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    try:
        result = run_scan(args.url, args.allow_host)
    except RefusedTarget as exc:
        print(f"Refused: {exc}", file=sys.stderr)
        return EXIT_REFUSED
    except FetchError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return EXIT_FETCH_ERROR

    print_result(result)

    if args.fail_on:
        threshold = Severity[args.fail_on.upper()]
        if any(f.severity >= threshold for f in result.findings):
            return EXIT_FINDINGS
    return EXIT_OK


if __name__ == "__main__":
    sys.exit(main())
