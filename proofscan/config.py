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

    # Places we are allowed to touch but must not. Not about permission, about
    # not wrecking our own results. A scanner that submits every form it finds
    # will eventually submit one that changes the thing it is measuring, and
    # then every finding after that is meaningless.
    #
    # This is not paranoia. On the first real scan of DVWA the scanner posted to
    # security.php, set the security level to "impossible", carried on scanning
    # the now fully patched app, found nothing, and reported a clean site.
    avoid: tuple = (
        # ends our own session
        "logout", "log-out", "logoff", "signout", "sign-out",
        # changes how the target behaves, so changes what the scan means
        "security.php", "settings", "preferences", "/config",
        # rebuilds or destroys the target
        "setup.php", "install.php", "/reset",
    )

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

    def should_avoid(self, url):
        """In scope, but touching it would wreck the scan."""
        lowered = url.lower()
        return any(word in lowered for word in self.avoid)


class OutOfScopeError(Exception):
    pass
