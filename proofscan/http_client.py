"""All requests go through here, so the scope check and rate limit always apply."""
import time
from dataclasses import dataclass
from urllib.parse import urljoin

import httpx

from .config import OutOfScopeError

USER_AGENT = "ProofScan/0.1 (college project, authorised testing only)"

REDIRECT_STATUSES = (301, 302, 303, 307, 308)

# a redirect loop is somebody else's bug, not something to chase forever
MAX_REDIRECTS = 5


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
    def __init__(self, scope, auth=None, cookies=None):
        self.scope = scope
        self.auth = auth
        self._min_gap = 1.0 / scope.requests_per_second if scope.requests_per_second else 0
        self._last_request_at = 0.0
        self._client = httpx.Client(
            timeout=scope.timeout_seconds,
            # redirects are followed here, by hand, one hop at a time. httpx
            # would follow them internally and the scope check would only ever
            # see the first url, so a redirect could walk us onto a host we were
            # never allowed to touch.
            follow_redirects=False,
            headers={"User-Agent": USER_AGENT},
            # Some apps keep part of their state in a cookie rather than in the
            # session, and start in whatever mode the cookie is missing. DVWA is
            # the example that cost an afternoon: it hands out
            # security=impossible at login, which is the fully patched build, so
            # a scanner that never sets the cookie is scanning an app with
            # nothing wrong with it and cannot tell.
            cookies=cookies or {},
        )
        self.request_count = 0
        self.session_recoveries = 0     # times we noticed we had been logged out
        self._relogging = False

    def _wait(self):
        gap = time.monotonic() - self._last_request_at
        if gap < self._min_gap:
            time.sleep(self._min_gap - gap)

    def _send(self, method, url, **kwargs):
        """One request. Scope is checked here, so every hop is checked."""
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

    def request(self, method, url, follow_redirects=False, **kwargs):
        """Send a request, optionally following redirects.

        Redirects stay off by default. The detectors and validators compare one
        response against another, and a redirect that gets followed hides the
        thing they are looking at. Logging in is the opposite case: those flows
        are all redirects, so the login code turns this on for itself.
        """
        response = self._send(method, url, **kwargs)

        if follow_redirects:
            response = self._follow(response, method, kwargs)

        return self._recover_session(response, method, url, follow_redirects, kwargs)

    def _follow(self, response, method, kwargs):
        total_ms = response.elapsed_ms

        for _ in range(MAX_REDIRECTS):
            if response.status not in REDIRECT_STATUSES:
                break
            location = response.headers.get("location")
            if not location:
                break

            target = urljoin(response.url, location)

            # 303 always becomes a GET, and every browser turns a 302 after a
            # POST into one too. Carrying the form body onward would resend it
            # to a page that never asked for it.
            if response.status == 303 or (response.status == 302 and method.upper() == "POST"):
                method = "GET"
                kwargs = {k: v for k, v in kwargs.items()
                          if k not in ("data", "json", "content", "files")}

            response = self._send(method, target, **kwargs)
            total_ms += response.elapsed_ms

        response.elapsed_ms = total_ms
        return response

    def _recover_session(self, response, method, url, follow_redirects, kwargs):
        """If we have been logged out, log back in and ask again, once.

        Sessions expire part way through a scan. Without this the scanner
        carries on happily requesting the login page for every remaining point
        and reports that it found nothing wrong, which is the worst possible
        way to fail.
        """
        if self.auth is None or self._relogging:
            return response
        if not self.auth.looks_logged_out(response):
            return response

        self._relogging = True
        try:
            recovered = self.auth.login(self)
        finally:
            self._relogging = False

        if not recovered:
            return response

        self.session_recoveries += 1
        retry = self._send(method, url, **kwargs)
        if follow_redirects:
            retry = self._follow(retry, method, kwargs)
        return retry

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
