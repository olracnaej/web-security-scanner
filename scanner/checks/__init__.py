"""Registry of checks. Each check takes a ScanContext and returns Findings."""

from scanner.checks import cookies, exposed_files, headers, tls, wordpress
from scanner.context import ScanContext


def _headers(ctx: ScanContext):
    return headers.check(ctx.response)


def _cookies(ctx: ScanContext):
    return cookies.check(ctx.response)


CHECKS = (_headers, _cookies, tls.check, exposed_files.check, wordpress.check)
