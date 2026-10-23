"""JSON and HTML reports.

Everything a scanned site can influence (header values, file names, evidence)
is HTML-escaped, and the HTML report carries its own strict Content-Security-
Policy and no scripts. Cookie values and file contents never get this far:
the checks do not keep them.
"""

from __future__ import annotations

import html
import json
from datetime import datetime, timezone
from pathlib import Path

from scanner import __version__
from scanner.engine import ScanResult
from scanner.models import Severity

SCHEMA_VERSION = 1
SEVERITY_ORDER = ("high", "medium", "low", "info")


def build_report(result: ScanResult) -> dict:
    scanned_at = result.scanned_at or datetime.now(timezone.utc)
    resp = result.response
    counts = {label: 0 for label in SEVERITY_ORDER}
    findings = []
    for f in result.findings:
        counts[f.severity.label] += 1
        findings.append({
            "check_id": f.check_id,
            "title": f.title,
            "severity": f.severity.label,
            "description": f.description,
            "recommendation": f.recommendation,
            "evidence": f.evidence,
        })
    return {
        "schema_version": SCHEMA_VERSION,
        "tool": {"name": "web-security-scanner", "version": __version__},
        "scanned_at": scanned_at.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "target": {
            "url": resp.target.url,
            "http_status": resp.status,
            "requests_made": result.requests_made,
            "redirects_followed": len(resp.redirects),
            "tls_verified": resp.tls_verified,
        },
        "score": {
            "value": result.score.value,
            "max": 100,
            "grade": result.score.grade,
            "breakdown": result.score.breakdown,
        },
        "counts": counts,
        "findings": findings,
    }


def to_json(report: dict) -> str:
    return json.dumps(report, indent=2, ensure_ascii=False) + "\n"


# ----------------------------------------------------------------------------
# HTML
# ----------------------------------------------------------------------------

CSS = """
:root{color-scheme:light dark;--bg:#f4f6f9;--card:#fff;--text:#1b2230;--muted:#586174;--line:#dfe3ea;
--high:#b42318;--medium:#b54708;--low:#7a5f00;--info:#175cd3;
--gA:#067647;--gB:#1a7f4b;--gC:#7a5f00;--gD:#b54708;--gF:#b42318}
@media (prefers-color-scheme:dark){:root{--bg:#0e1218;--card:#161b24;--text:#e7eaf1;--muted:#9aa3b4;--line:#283042;
--high:#ff8f85;--medium:#ffb36b;--low:#e8c963;--info:#82b3ff;
--gA:#4ade80;--gB:#6ee7a0;--gC:#e8c963;--gD:#ffb36b;--gF:#ff8f85}}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--text);font:16px/1.55 system-ui,-apple-system,"Segoe UI",Roboto,sans-serif}
.wrap{max-width:880px;margin:0 auto;padding:32px 20px 48px}
.eyebrow{margin:0;color:var(--muted);font-size:13px;letter-spacing:.08em;text-transform:uppercase}
h1{margin:4px 0 6px;font-size:26px;overflow-wrap:anywhere}
.meta{margin:0;color:var(--muted);font-size:14px}
.summary{display:flex;gap:24px;align-items:center;flex-wrap:wrap;margin:28px 0;padding:22px;background:var(--card);border:1px solid var(--line);border-radius:14px}
.grade{width:108px;height:108px;border-radius:50%;border:5px solid var(--gc);display:flex;flex-direction:column;align-items:center;justify-content:center;color:var(--gc)}
.grade .letter{font-size:44px;font-weight:700;line-height:1}
.grade .score{font-size:14px;color:var(--text)}
.gA{--gc:var(--gA)}.gB{--gc:var(--gB)}.gC{--gc:var(--gC)}.gD{--gc:var(--gD)}.gF{--gc:var(--gF)}
.counts{display:flex;gap:12px;flex-wrap:wrap;list-style:none;margin:0;padding:0}
.counts li{min-width:84px;padding:10px 14px;border:1px solid var(--line);border-radius:10px;text-align:center}
.counts b{display:block;font-size:24px;line-height:1.1}
.counts span{font-size:13px;color:var(--muted)}
.counts .high b{color:var(--high)}.counts .medium b{color:var(--medium)}.counts .low b{color:var(--low)}.counts .info b{color:var(--info)}
h2{margin:32px 0 12px;font-size:18px}
.finding{margin:0 0 12px;padding:16px 18px;background:var(--card);border:1px solid var(--line);border-left:5px solid var(--sev);border-radius:10px}
.finding.high{--sev:var(--high)}.finding.medium{--sev:var(--medium)}.finding.low{--sev:var(--low)}.finding.info{--sev:var(--info)}
.finding h3{margin:0 0 2px;font-size:16px}
.badge{font-size:12px;font-weight:700;letter-spacing:.06em;color:var(--sev);margin-right:8px}
.cid{margin:0 0 8px;color:var(--muted);font:13px ui-monospace,Consolas,monospace}
.finding p{margin:6px 0}
.found code{font:13px ui-monospace,Consolas,monospace;background:var(--bg);padding:2px 6px;border-radius:5px;overflow-wrap:anywhere}
table{border-collapse:collapse;width:100%;max-width:420px;font-size:14px}
th,td{padding:6px 10px;border-bottom:1px solid var(--line);text-align:left}
.small{color:var(--muted);font-size:13px}
footer{margin-top:36px;padding-top:16px;border-top:1px solid var(--line)}
@media print{body{background:#fff}.finding,.summary{break-inside:avoid}}
"""

CSP = "default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'"


def _e(value) -> str:
    return html.escape(str(value), quote=True)


def _finding_html(f: dict) -> str:
    evidence = (
        f'<p class="found"><strong>Found:</strong> <code>{_e(f["evidence"])}</code></p>'
        if f["evidence"] else ""
    )
    return (
        f'<article class="finding {_e(f["severity"])}">'
        f'<h3><span class="badge">{_e(f["severity"].upper())}</span>{_e(f["title"])}</h3>'
        f'<p class="cid">{_e(f["check_id"])}</p>'
        f'<p>{_e(f["description"])}</p>'
        f'<p><strong>Fix:</strong> {_e(f["recommendation"])}</p>'
        f"{evidence}</article>"
    )


def to_html(report: dict) -> str:
    score, target, counts = report["score"], report["target"], report["counts"]

    groups = []
    for label in SEVERITY_ORDER:
        items = [f for f in report["findings"] if f["severity"] == label]
        if items:
            groups.append(
                f"<h2>{label.capitalize()} ({len(items)})</h2>"
                + "".join(_finding_html(f) for f in items)
            )
    body_findings = "".join(groups) or "<p>No findings. Nothing to fix from these checks.</p>"

    pills = "".join(
        f'<li class="{label}"><b>{counts[label]}</b><span>{label}</span></li>'
        for label in SEVERITY_ORDER
    )
    rows = "".join(
        f'<tr><td>{label.capitalize()}</td><td>{score["breakdown"][label]["types"]}</td>'
        f'<td>-{score["breakdown"][label]["points"]}</td></tr>'
        for label in SEVERITY_ORDER
    )
    tls = {True: "verified", False: "not verified", None: "not applicable (plain HTTP)"}[target["tls_verified"]]

    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta http-equiv="Content-Security-Policy" content="{_e(CSP)}">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Security report: {_e(target["url"])}</title>
<style>{CSS}</style></head>
<body><div class="wrap">
<header>
<p class="eyebrow">Web Security Scanner report</p>
<h1>{_e(target["url"])}</h1>
<p class="meta">Scanned {_e(report["scanned_at"])} &middot; HTTP {_e(target["http_status"])} &middot; {_e(target["requests_made"])} requests &middot; TLS certificate: {_e(tls)}</p>
</header>
<section class="summary" aria-label="Summary">
<div class="grade g{_e(score["grade"])}"><span class="letter">{_e(score["grade"])}</span><span class="score">{_e(score["value"])}/{_e(score["max"])}</span></div>
<ul class="counts">{pills}</ul>
</section>
<main>{body_findings}</main>
<footer>
<h2>How the score was calculated</h2>
<table><tr><th>Severity</th><th>Problem types</th><th>Points</th></tr>{rows}</table>
<p class="small">Start at 100, subtract 20 per high, 8 per medium and 3 per low problem type (each type counts once). Any high finding caps the grade at D.</p>
<p class="small">Generated by web-security-scanner {_e(report["tool"]["version"])}. Only scan sites you own or have written permission to test.</p>
</footer>
</div></body></html>
"""


def write_text(path: str | Path, text: str) -> Path:
    out = Path(path)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(text, encoding="utf-8")
    return out
