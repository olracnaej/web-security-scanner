# Web Security Scanner

A small Python tool that checks a website for common security hygiene problems.
Built step by step as a portfolio project. **Only scan sites you own or have written permission to test.**

## Status

- [x] Step 1: project skeleton, CLI, safety guard
- [x] Step 2: security headers and cookie checks
- [ ] Step 3: TLS, exposed files, WordPress checks
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

## Usage

```bash
python -m scanner scan http://127.0.0.1:8001
python -m scanner scan https://my-client-site.com --allow-host my-client-site.com
python -m scanner scan http://127.0.0.1:8001 --fail-on medium   # exit code 1 if medium+ found (CI)
```

Exit codes: `0` ok, `1` findings at/above `--fail-on`, `2` target refused, `3` could not fetch.

Try it on your own machine with a plain local server (it has no security headers, so it shows many findings):

```bash
python -m http.server 8001 --bind 127.0.0.1
```

## Tests

```bash
pip install pytest
python -m pytest
```
