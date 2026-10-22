# Web Security Scanner

A small Python tool that checks a website for common security hygiene problems.
Built step by step as a portfolio project. **Only scan sites you own or have written permission to test.**

## Status

- [x] Step 1: project skeleton, CLI, safety guard
- [ ] Step 2: security headers and cookie checks
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

## Usage

```bash
python -m scanner scan http://127.0.0.1:8001
python -m scanner scan https://my-client-site.com --allow-host my-client-site.com
```

## Tests

```bash
pip install pytest
python -m pytest
```
