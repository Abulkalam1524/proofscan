"""Logging in, and noticing when we have been logged out again.

Nearly every real target keeps its interesting pages behind a login. Without
this the crawler gets one redirect to the login page, finds no links on it and
stops, which looks exactly like a clean site.

The login itself is a form post, with two things that trip people up. Most login
forms carry a hidden csrf token that changes every time, so the form has to be
fetched and read rather than guessed at. And logins run on redirects, so this is
the one place that follows them.
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
        # where to look to see whether the login took. the site root by default,
        # because asking the login page is no use: plenty of apps, dvwa among
        # them, keep serving the login form there whether you are logged in or
        # not, so it always looks like a failure.
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
        """Pull the login form apart and take every named field with us.

        This is the part that makes it work on more than one site. Hidden fields
        get collected along with the visible ones, so csrf tokens, whatever they
        are called, come with us without anyone naming them. Submit buttons are
        collected too, because some apps check for the button rather than the
        username, and dropping it means the login silently fails.
        """
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
        """Find a link that only exists for someone who is logged in.

        The logout link is the obvious one, and it is on almost every
        authenticated page because that is where you need it to be. Its
        disappearance is a far better signal than a password box appearing.
        """
        soup = BeautifulSoup(body, "lxml")
        for a in soup.find_all("a", href=True):
            href = a["href"].lower()
            if any(word in href for word in ("logout", "log-out", "logoff", "signout")):
                return a["href"]
        return None

    def looks_logged_out(self, response):
        """Have we been thrown out? Only says yes on real evidence.

        Deliberately hard to convince. Saying yes while we are still logged in
        sets off a pointless re-login, and doing that on every page wastes the
        request budget on a problem that is not there.

        A password box on the page is not enough on its own, which is the trap
        this walked straight into on DVWA. Change your password, brute force and
        captcha are all ordinary authenticated pages that happen to contain one,
        so the naive check reported being logged out three times in one crawl
        and logged back in three times for nothing. If the page still carries
        the logged in marker, we are still logged in, whatever else is on it.
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
