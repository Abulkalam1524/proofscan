"""Crawler. Walks the site and collects every place we can put input into."""
from collections import deque
from dataclasses import dataclass, field
from urllib.parse import parse_qsl, urldefrag, urljoin, urlparse

from bs4 import BeautifulSoup


@dataclass(frozen=True)
class InjectionPoint:
    url: str
    method: str
    param: str
    source: str                       # "query" or "form"
    other_params: tuple = field(default=())
    value: str = ""                   # the value it already had, used as a probe base

    def __str__(self):
        return f"{self.method} {self.url} [{self.param}] ({self.source})"

    def base_params(self):
        return dict(self.other_params)


@dataclass
class CrawlResult:
    pages: list
    injection_points: list
    avoided: list = field(default_factory=list)   # links we deliberately did not follow

    def summary(self):
        return f"{len(self.pages)} pages, {len(self.injection_points)} injection points"


class Crawler:
    def __init__(self, client, scope):
        self.client = client
        self.scope = scope

    def crawl(self, start_url):
        queue = deque([start_url])
        seen = set()
        pages = []
        points = {}
        self.avoided = []

        while queue and len(pages) < self.scope.max_pages:
            url = urldefrag(queue.popleft())[0]
            if url in seen or not self.scope.allows(url):
                continue
            seen.add(url)

            try:
                # redirects get followed while crawling, because this is about
                # finding pages and plenty of sites answer / with a redirect to
                # the real front page. the detectors keep them switched off,
                # since a followed redirect hides the response they compare.
                response = self.client.get(url, follow_redirects=True)
            except Exception as e:
                print(f"  [!] {url}: {e}")
                continue

            # after a redirect the page we actually got is somewhere else, and
            # that is the one with the parameters on it
            landed = urldefrag(response.url)[0]
            seen.add(landed)
            pages.append(landed)

            for p in self._query_points(landed):
                self._keep(points, p)

            if "html" not in response.headers.get("content-type", ""):
                continue

            soup = BeautifulSoup(response.body, "lxml")

            for p in self._form_points(soup, landed):
                self._keep(points, p)

            for a in soup.find_all("a", href=True):
                link = urldefrag(urljoin(landed, a["href"]))[0]
                if not self.scope.allows(link) or link in seen:
                    continue
                if self.scope.should_avoid(link):
                    # never queued, never requested. following one of these logs
                    # us out and the rest of the crawl silently becomes an
                    # anonymous one.
                    if link not in self.avoided:
                        self.avoided.append(link)
                    continue
                queue.append(link)

        return CrawlResult(pages, list(points.values()), self.avoided)

    def _keep(self, points, point):
        """Collect an injection point, unless submitting to it would spoil the scan.

        Reading one of these pages is harmless. Posting a payload into it is not,
        and the crawler is where the decision belongs, because a point that never
        gets collected can never be sent anything by anyone downstream.
        """
        if self.scope.should_avoid(point.url):
            if point.url not in self.avoided:
                self.avoided.append(point.url)
            return
        points[(point.url, point.method, point.param)] = point

    @staticmethod
    def _query_points(url):
        query = urlparse(url).query
        if not query:
            return []
        pairs = parse_qsl(query, keep_blank_values=True)
        base = url.split("?", 1)[0]
        return [
            InjectionPoint(base, "GET", name, "query",
                           tuple((k, v) for k, v in pairs if k != name),
                           value=val)
            for name, val in pairs
        ]

    def _form_points(self, soup, page_url):
        found = []

        for form in soup.find_all("form"):
            action = urljoin(page_url, form.get("action") or page_url)
            method = (form.get("method") or "GET").upper()

            # Two password boxes means change your password, or register, or
            # reset. One box is a login, which is a fair target. Two is a form
            # whose whole purpose is to change the credentials we are using.
            #
            # This is not hypothetical. Once submit buttons started being sent,
            # DVWA's change password form began to fire, the validator's own
            # baseline value went into both boxes at once, they matched, and the
            # scanner changed the admin password to "test" and locked itself
            # out of the target half way through the scan.
            if len(form.find_all("input", attrs={"type": "password"})) >= 2:
                if action not in self.avoided:
                    self.avoided.append(action)
                continue

            # Everything named goes in the payload, submit buttons included.
            # Plenty of apps check for the button rather than the field and do
            # nothing at all without it. DVWA's sql injection page is one: drop
            # Submit and it renders the form and never runs the query, so the
            # response never changes and the page looks safe.
            fields = []
            for tag in form.find_all(["input", "textarea", "select"]):
                name = tag.get("name")
                if not name:
                    continue
                is_button = tag.get("type", "").lower() in ("submit", "button", "image")
                fields.append((name, tag.get("value") or "test", is_button))

            payload = [(name, val) for name, val, _ in fields]

            for name, val, is_button in fields:
                if is_button:
                    continue        # sent with every request, never injected into
                found.append(InjectionPoint(
                    action, method, name, "form",
                    tuple((k, v) for k, v in payload if k != name),
                    value=val))

        return found
