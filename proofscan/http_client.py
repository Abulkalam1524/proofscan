"""All requests go through here, so the scope check and rate limit always apply."""
import time
from dataclasses import dataclass

import httpx

from .config import OutOfScopeError

USER_AGENT = "ProofScan/0.1 (college project, authorised testing only)"


@dataclass
class Response:
    url: str
    method: str
    status: int
    headers: dict
    body: str
    elapsed_ms: float

    @property
    def length(self):
        return len(self.body)


class HttpClient:
    def __init__(self, scope):
        self.scope = scope
        self._min_gap = 1.0 / scope.requests_per_second if scope.requests_per_second else 0
        self._last_request_at = 0.0
        self._client = httpx.Client(
            timeout=scope.timeout_seconds,
            follow_redirects=False,   # we want to see the redirect, not follow it
            headers={"User-Agent": USER_AGENT},
        )
        self.request_count = 0

    def _wait(self):
        gap = time.monotonic() - self._last_request_at
        if gap < self._min_gap:
            time.sleep(self._min_gap - gap)

    def request(self, method, url, **kwargs):
        if not self.scope.allows(url):
            raise OutOfScopeError(f"out of scope: {url}")

        self._wait()
        start = time.perf_counter()
        r = self._client.request(method, url, **kwargs)
        elapsed = (time.perf_counter() - start) * 1000
        self._last_request_at = time.monotonic()
        self.request_count += 1

        return Response(
            url=str(r.url),
            method=method.upper(),
            status=r.status_code,
            headers=dict(r.headers),
            body=r.text,
            elapsed_ms=elapsed,
        )

    def get(self, url, **kwargs):
        return self.request("GET", url, **kwargs)

    def post(self, url, **kwargs):
        return self.request("POST", url, **kwargs)

    def close(self):
        self._client.close()

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()
