"""Runs a scan: guard, fetch, checks, score."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone

from scanner.checks import CHECKS
from scanner.context import ScanContext
from scanner.http import Response, fetch
from scanner.models import Finding
from scanner.safety import authorize_target
from scanner.scoring import Score, score_findings


@dataclass(frozen=True)
class ScanResult:
    response: Response
    findings: tuple[Finding, ...]
    requests_made: int
    score: Score
    scanned_at: datetime


def run_scan(url: str, allow_hosts=(), delay: float | None = None) -> ScanResult:
    target = authorize_target(url, allow_hosts)
    response = fetch(target, allow_hosts=allow_hosts)
    ctx = ScanContext(response, tuple(allow_hosts), delay=delay)

    findings: list[Finding] = []
    for check in CHECKS:
        findings.extend(check(ctx))
    findings.sort(key=lambda f: (-f.severity, f.check_id))
    return ScanResult(
        response,
        tuple(findings),
        1 + ctx.probes_made,
        score_findings(findings),
        datetime.now(timezone.utc),
    )
