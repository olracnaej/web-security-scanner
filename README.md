# Web Security Scanner

A small Python tool that checks a website for common security hygiene problems.
Built step by step as a portfolio project. **Only scan sites you own or have written permission to test.**

## Status

- [x] Step 1: project skeleton, CLI, safety guard
- [x] Step 2: security headers and cookie checks
- [x] Step 3: TLS, exposed files, WordPress checks
- [ ] Step 4: three deliberately misconfigured local test sites
- [ ] Step 5: scoring and HTML/JSON report

## Safety guard

Before any request is sent, the target is checked (`scanner/safety.py`):

- Only `http://` and `https://`, no credentials in the URL.
- `localhost` / `127.0.0.1` / `::1` are allowed by default.
- Any other host needs its exact name passed with `--allow-host`. No wildcards.
- Cloud metadata (`169.254.x.x`), multicast, reserved and shared ranges are always refused.
- Every IP a name resolves to is checked, and later requests will connect to those exact IPs (no DNS rebinding gap).
- Redirects are only followed on the same host.

## What it checks so far

- **Headers:** HSTS, Content-Security-Policy (and weak policies), clickjacking protection, `nosniff`, Referrer-Policy, Permissions-Policy, version leaks in `Server` / `X-Powered-By`.
- **Cookies:** `Secure`, `HttpOnly`, `SameSite` on every `Set-Cookie`. Cookie values are never printed or stored.

- **TLS:** certificate validity (expired, self-signed, wrong host name), expiry within 30 days, obsolete TLS 1.0/1.1 still accepted, site served over plain HTTP, missing HTTP to HTTPS redirect.
- **Exposed files:** `.git`, `.env`, `.htpasswd`, private keys, backups and SQL dumps, `phpinfo`, admin panels, directory listing and more (about 30 paths). A hit needs HTTP 200 **and** matching content, so sites that answer 200 to everything cause no false alarms. File contents are never stored or printed.
- **WordPress** (only when detected): version exposure and whether it is behind the current series, readme, plugins visible in the page, public user list, author enumeration, `xmlrpc.php`, `wp-config` backups, `debug.log`, directory listing in uploads/plugins.

## Being gentle

A scan sends about 30 to 40 requests, with a 0.1 s pause between extra requests (`--delay` changes it) and a hard cap of 80. Extra requests only go to the same, already authorized host.

## Known limits

- The obsolete-TLS test only works if the OpenSSL on your computer can still speak TLS 1.0/1.1; if not, it reports nothing.
- WordPress "outdated" uses reference data in `scanner/data.py` (checked 2026-10-21). After 180 days the finding switches itself off instead of guessing.
- Plugin versions are not checked.

## Usage

```bash
python -m scanner scan http://127.0.0.1:8001
python -m scanner scan https://my-client-site.com --allow-host my-client-site.com
python -m scanner scan http://127.0.0.1:8001 --fail-on medium   # exit code 1 if medium+ found (CI)
```

Exit codes: `0` ok, `1` findings at/above `--fail-on`, `2` target refused, `3` could not fetch.

Try it on your own machine with a plain local server (it has no security headers, so it shows many findings; start it inside a folder that contains a `.git` folder to see the exposed-repository finding):

```bash
python -m http.server 8001 --bind 127.0.0.1
```

## Tests

```bash
pip install pytest
python -m pytest
```
