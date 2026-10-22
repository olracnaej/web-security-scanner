"""Command line interface."""

from __future__ import annotations

import argparse
import sys

from scanner import __version__
from scanner.safety import RefusedTarget, authorize_target

EXIT_OK = 0
EXIT_REFUSED = 2


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
        "--allow-host",
        action="append",
        default=[],
        metavar="HOST",
        help="exact host name you have permission to scan (repeatable). "
        "Not needed for localhost.",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    try:
        target = authorize_target(args.url, args.allow_host)
    except RefusedTarget as exc:
        print(f"Refused: {exc}", file=sys.stderr)
        return EXIT_REFUSED

    print(f"Authorized: {target.host}:{target.port} ({target.reason})")
    print(f"Resolved to: {', '.join(target.addresses)}")
    print("Checks are added in the next steps.")
    return EXIT_OK


if __name__ == "__main__":
    sys.exit(main())
