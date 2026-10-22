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
                # redirects are followed while crawling, plenty of sites redirect / somewhere.
                # the detectors keep them off
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
        """Collect an injection point, unless submitting to it would change the target."""
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

            # Two password boxes is change password, register or reset. Never submit it:
            # on DVWA this changed the admin password mid scan.
            if len(form.find_all("input", attrs={"type": "password"})) >= 2:
                if action not in self.avoided:
                    self.avoided.append(action)
                continue

            # Every named field goes in, submit buttons too. DVWA's sqli page never runs
            # the query without Submit=Submit.
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
