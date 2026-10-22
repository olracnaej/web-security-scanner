"""Runs a scan: guard, fetch, checks."""

from __future__ import annotations

from dataclasses import dataclass

from scanner.checks import CHECKS
from scanner.http import Response, fetch
from scanner.models import Finding
from scanner.safety import authorize_target


@dataclass(frozen=True)
class ScanResult:
    response: Response
    findings: tuple[Finding, ...]


def run_scan(url: str, allow_hosts=()) -> ScanResult:
    target = authorize_target(url, allow_hosts)
    response = fetch(target, allow_hosts=allow_hosts)
    findings = [f for check in CHECKS for f in check(response)]
    findings.sort(key=lambda f: (-f.severity, f.check_id))
    return ScanResult(response, tuple(findings))
