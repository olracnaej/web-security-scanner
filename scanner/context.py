"""What a check receives: the main response plus a safe way to probe more paths."""

from __future__ import annotations

import time
from dataclasses import dataclass, replace
from urllib.parse import urljoin, urlsplit

from scanner.http import TIMEOUT, FetchError, Response, fetch_once
from scanner.safety import AuthorizedTarget

DEFAULT_DELAY = 0.1  # seconds between probes: be gentle with small sites
MAX_PROBES = 80      # hard cap on extra requests per scan
PROBE_BODY_LIMIT = 65_536


@dataclass
class ScanContext:
    response: Response
    allow_hosts: tuple[str, ...] = ()
    delay: float | None = None
    timeout: float = TIMEOUT
    probes_made: int = 0

    @property
    def target(self) -> AuthorizedTarget:
        return self.response.target

    def probe(self, path: str) -> Response | None:
        """GET another path on the SAME authorized host. Redirects are not
        followed. Returns None on network errors or when the cap is reached."""
        if self.probes_made >= MAX_PROBES:
            return None
        new_url = urljoin(self.target.url, path)
        old, new = urlsplit(self.target.url), urlsplit(new_url)
        if (new.scheme, new.netloc) != (old.scheme, old.netloc):
            raise ValueError(f"probe path {path!r} would leave the authorized host")

        delay = DEFAULT_DELAY if self.delay is None else self.delay
        if delay > 0:
            time.sleep(delay)
        self.probes_made += 1
        try:
            return fetch_once(replace(self.target, url=new_url), self.timeout, PROBE_BODY_LIMIT)
        except FetchError:
            return None
