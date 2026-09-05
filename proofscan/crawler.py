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

    def __str__(self):
        return f"{self.method} {self.url} [{self.param}] ({self.source})"

    def base_params(self):
        return dict(self.other_params)


@dataclass
class CrawlResult:
    pages: list
    injection_points: list

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

        while queue and len(pages) < self.scope.max_pages:
            url = urldefrag(queue.popleft())[0]
            if url in seen or not self.scope.allows(url):
                continue
            seen.add(url)

            try:
                response = self.client.get(url)
            except Exception as e:
                print(f"  [!] {url}: {e}")
                continue

            pages.append(url)

            for p in self._query_points(url):
                points[(p.url, p.method, p.param)] = p

            if "html" not in response.headers.get("content-type", ""):
                continue

            soup = BeautifulSoup(response.body, "lxml")

            for p in self._form_points(soup, url):
                points[(p.url, p.method, p.param)] = p

            for a in soup.find_all("a", href=True):
                link = urldefrag(urljoin(url, a["href"]))[0]
                if self.scope.allows(link) and link not in seen:
                    queue.append(link)

        return CrawlResult(pages, list(points.values()))

    @staticmethod
    def _query_points(url):
        query = urlparse(url).query
        if not query:
            return []
        pairs = parse_qsl(query, keep_blank_values=True)
        base = url.split("?", 1)[0]
        return [
            InjectionPoint(base, "GET", name, "query",
                           tuple((k, v) for k, v in pairs if k != name))
            for name, _ in pairs
        ]

    @staticmethod
    def _form_points(soup, page_url):
        found = []

        for form in soup.find_all("form"):
            action = urljoin(page_url, form.get("action") or page_url)
            method = (form.get("method") or "GET").upper()

            fields = []
            for tag in form.find_all(["input", "textarea", "select"]):
                name = tag.get("name")
                if not name:
                    continue
                if tag.get("type", "").lower() in ("submit", "button", "image"):
                    continue
                fields.append((name, tag.get("value") or "test"))

            for name, _ in fields:
                found.append(InjectionPoint(
                    action, method, name, "form",
                    tuple((k, v) for k, v in fields if k != name)))

        return found
