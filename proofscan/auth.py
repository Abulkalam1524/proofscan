"""Form login, and noticing when the session has been lost.

Without a login most targets show only the login page, which looks like a clean site.
"""
from urllib.parse import urljoin, urlparse

from bs4 import BeautifulSoup


def _looks_like_a_login_page(body):
    """A password box is the giveaway. Nothing else on a site has one."""
    if not body:
        return False
    soup = BeautifulSoup(body, "lxml")
    return soup.find("input", attrs={"type": "password"}) is not None


class FormLogin:
    """Log in by posting a form, the way a browser would."""

    def __init__(self, login_url, username, password,
                 username_field="username", password_field="password",
                 extra_fields=None, verify_url=None):
        self.login_url = login_url
        self.username = username
        self.password = password
        self.username_field = username_field
        self.password_field = password_field
        self.extra_fields = extra_fields or {}
        # where to check that the login took. not the login page, which dvwa keeps
        # serving whether you are logged in or not
        self.verify_url = verify_url or self._root_of(login_url)
        self.logged_in_at_least_once = False
        # something that only appears once we are logged in, picked up from the
        # site itself at login time. see looks_logged_out for why a password box
        # on its own is not good enough.
        self.marker = None

    @staticmethod
    def _root_of(url):
        parts = urlparse(url)
        return f"{parts.scheme}://{parts.netloc}/"

    def __str__(self):
        return f"form login at {self.login_url} as {self.username}"

    def _read_form(self, body):
        """Read the login form and keep every named field, hidden csrf tokens and buttons included."""
        soup = BeautifulSoup(body, "lxml")

        form = None
        for candidate in soup.find_all("form"):
            if candidate.find("input", attrs={"type": "password"}):
                form = candidate
                break
        if form is None:
            form = soup.find("form")
        if form is None:
            return None, {}

        fields = {}
        for tag in form.find_all(["input", "textarea", "select"]):
            name = tag.get("name")
            if name:
                fields[name] = tag.get("value") or ""

        return form.get("action"), fields

    def login(self, client):
        """Do the login. Returns True only if it can show that it worked."""
        page = client.request("GET", self.login_url, follow_redirects=True)
        action, fields = self._read_form(page.body)
        if not fields:
            return False

        fields[self.username_field] = self.username
        fields[self.password_field] = self.password
        fields.update(self.extra_fields)

        target = urljoin(page.url, action) if action else page.url
        client.request("POST", target, follow_redirects=True, data=fields)

        # never trust the post. a login that quietly failed still returns 200,
        # and a scanner that believes it is logged in when it is not will report
        # a clean site. ask for a real page and see who we are.
        proof = client.request("GET", self.verify_url, follow_redirects=True)
        worked = not _looks_like_a_login_page(proof.body)

        if worked and self.marker is None:
            self.marker = self._find_marker(proof.body)

        self.logged_in_at_least_once = self.logged_in_at_least_once or worked
        return worked

    @staticmethod
    def _find_marker(body):
        """Find a link only a logged in user sees, usually logout."""
        soup = BeautifulSoup(body, "lxml")
        for a in soup.find_all("a", href=True):
            href = a["href"].lower()
            if any(word in href for word in ("logout", "log-out", "logoff", "signout")):
                return a["href"]
        return None

    def looks_logged_out(self, response):
        """True only on real evidence that we were logged out.

        A password box alone is not enough: DVWA's change password, brute force
        and captcha pages have one while logged in. If the logged in marker is
        still on the page, we are still in.
        """
        if not self.logged_in_at_least_once:
            return False        # never logged in, so nothing to be thrown out of

        location = response.headers.get("location", "")
        if location and self._login_path() in location:
            return True

        if response.url.rstrip("/") == self.login_url.rstrip("/"):
            return False        # asking for the login page is not being logged out

        if self.marker and self.marker in (response.body or ""):
            return False        # the logout link is still there, so we are fine

        return _looks_like_a_login_page(response.body)

    def _login_path(self):
        return urlparse(self.login_url).path
