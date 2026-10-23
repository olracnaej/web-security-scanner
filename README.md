# Web Security Scanner

A small Python tool that checks a website for common security hygiene problems and turns the result into a score, a JSON report and a readable HTML report. Built for small business sites, with no third-party dependencies.

**Only scan sites you own or have written permission to test.** The tool enforces this: it scans `localhost` by default and refuses any other host unless you name it explicitly.

## What it checks

| Area | Examples |
|------|----------|
| **Headers** | HSTS, Content-Security-Policy (including weak policies), clickjacking protection, `nosniff`, Referrer-Policy, Permissions-Policy, version leaks in `Server` / `X-Powered-By` |
| **Cookies** | `Secure`, `HttpOnly`, `SameSite` on every `Set-Cookie`. Cookie values are never stored or printed |
| **TLS** | Expired, self-signed or wrong-host certificates, expiry within 30 days, obsolete TLS 1.0/1.1, plain-HTTP sites, missing HTTP to HTTPS redirect |
| **Exposed files** | `.git`, `.env`, `.htpasswd`, private keys, backups and SQL dumps, `phpinfo`, admin panels, directory listing (about 30 paths). A hit needs HTTP 200 **and** matching content, so sites that answer 200 to everything cause no false alarms. File contents are never stored or printed |
| **WordPress** (only when detected) | Version exposure and whether it is behind the current series, readme, plugins visible in the page, public user list, author enumeration, `xmlrpc.php`, `wp-config` backups, `debug.log`, directory listing in uploads/plugins |

## Usage

```bash
python -m scanner scan http://127.0.0.1:8101
python -m scanner scan https://my-client-site.com --allow-host my-client-site.com
python -m scanner scan http://127.0.0.1:8101 --html report.html --json report.json
python -m scanner scan https://my-client-site.com --allow-host my-client-site.com --fail-under 80
```

| Option | Meaning |
|--------|---------|
| `--allow-host HOST` | Exact host name you have permission to scan (repeatable). Not needed for localhost |
| `--html FILE` / `--json FILE` | Write a report |
| `--fail-under SCORE` | Exit code 1 if the score is below SCORE (for CI) |
| `--fail-on {low,medium,high}` | Exit code 1 if any finding is at least this severe |
| `--delay SECONDS` | Pause between extra requests (default 0.1) |

Exit codes: `0` ok, `1` score or severity limit hit, `2` target refused, `3` could not fetch, `4` could not write a report.

## Score and grade

| Step | Rule |
|------|------|
| Start | 100 points |
| Subtract | 20 per **high**, 8 per **medium**, 3 per **low** problem. Info costs nothing |
| Counting | Each *type* of problem counts once, at its worst severity (three cookies without `HttpOnly` are one problem) |
| Grade | A 90+, B 80+, C 70+, D 60+, otherwise F |
| Cap | Any high-severity finding limits the grade to D |

The HTML report shows this breakdown for every scan.

## Reports

- **HTML:** one self-contained file, no scripts, light and dark mode, printable. Everything a scanned site controls is escaped, and the file carries its own strict Content-Security-Policy.
- **JSON:** stable `schema_version`, for scripts and dashboards.

Cookie values and file contents never reach a report: the checks do not keep them.

## Safety by design

Before any request is sent, the target is checked (`scanner/safety.py`):

- Only `http://` and `https://`, no credentials in the URL.
- `localhost` / `127.0.0.1` / `::1` are allowed by default. Any other host needs its exact name in `--allow-host`, no wildcards.
- Cloud metadata (`169.254.x.x`), multicast, reserved and shared ranges are always refused.
- Every IP a name resolves to is checked, and requests connect to those exact IPs (no DNS rebinding gap).
- Redirects are only followed on the same host, and extra probes can never leave the authorized host.
- A scan sends about 30 to 50 requests with a pause between them, with a hard cap of 80.

## Practice targets

Three fake sites with deliberate mistakes live in `test_sites/`. They only listen on `127.0.0.1`, and every password in them is fake.

```bash
python -m test_sites all          # or: bare | leaky | wordpress
python -m scanner scan http://127.0.0.1:8101 --html bare.html
```

| Site | URL | What it shows | Result | Score | Reports |
|------|-----|---------------|--------|-------|---------|
| bare | http://127.0.0.1:8101 | No security headers, version leaks, cookies without flags | 5 medium, 7 low, 1 info | 53 (F) | [HTML](docs/sample-reports/bare.html), [JSON](docs/sample-reports/bare.json), [console](docs/sample-scans/bare.txt) |
| leaky | http://127.0.0.1:8102 | Exposed `.git`, `.env`, SQL dump, backup zip, `phpinfo`, directory listing | 4 high, 4 medium, 3 low, 1 info | 0 (F) | [HTML](docs/sample-reports/leaky.html), [JSON](docs/sample-reports/leaky.json), [console](docs/sample-scans/leaky.txt) |
| wordpress | http://127.0.0.1:8103 | Old WordPress, public user list, `xmlrpc.php`, leaked `wp-config` backup | 1 high, 6 medium, 9 low, 3 info | 5 (F) | [HTML](docs/sample-reports/wordpress.html), [JSON](docs/sample-reports/wordpress.json), [console](docs/sample-scans/wordpress.txt) |

The tests check that each site produces exactly its documented findings and score, so a change that alters the results is caught.

## Known limits

- The obsolete-TLS test only works if the OpenSSL on your computer can still speak TLS 1.0/1.1; if not, it reports nothing.
- WordPress "outdated" uses reference data in `scanner/data.py` (checked 2026-10-21). After 180 days the finding switches itself off instead of guessing.
- Plugin versions are not checked.
- This is a hygiene checker, not a penetration test. It reads pages; it does not try to break in.

## Tests

```bash
pip install pytest
python -m pytest
```

One test needs the `openssl` command and is skipped if it is not installed.

## Project layout

```
scanner/            the tool (safety guard, HTTP client, checks, scoring, reports, CLI)
scanner/checks/     headers, cookies, tls, exposed_files, wordpress
test_sites/         the three practice sites
tests/              automated tests
docs/               sample console output and sample reports
```
