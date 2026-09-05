"""Scope rules. What we are allowed to scan, and how fast."""
from dataclasses import dataclass, field
from urllib.parse import urlparse


@dataclass
class Scope:
    allowed_hosts: set = field(default_factory=set)

    requests_per_second: float = 10.0
    timeout_seconds: float = 10.0
    max_pages: int = 200

    # skips the timing tests, the only ones that make the server wait
    safe_mode: bool = False

    @classmethod
    def from_url(cls, url, **kwargs):
        host = urlparse(url).netloc
        if not host:
            raise ValueError(f"no host in url: {url}")
        return cls(allowed_hosts={host}, **kwargs)

    def allows(self, url):
        parsed = urlparse(url)
        if parsed.scheme not in ("http", "https"):
            return False
        return parsed.netloc in self.allowed_hosts


class OutOfScopeError(Exception):
    pass
