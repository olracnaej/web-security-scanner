"""Registry of checks. Each check takes a Response and returns Findings."""

from scanner.checks import cookies, headers

CHECKS = (headers.check, cookies.check)
