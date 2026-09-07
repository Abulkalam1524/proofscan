"""Logging in, staying logged in, and not wandering off the target.

Most of this needs no server. The awkward parts of authentication are decisions
made about a page that has already been fetched, so handing them a page directly
is quicker and lets the nasty cases be built exactly.

The DVWA tests at the bottom skip themselves if the container is not up.
"""
import pytest

from proofscan.auth import FormLogin, _looks_like_a_login_page
from proofscan.config import OutOfScopeError, Scope
from proofscan.crawler import Crawler
from proofscan.http_client import HttpClient, Response

DVWA = "http://127.0.0.1:8080"

LOGIN_HTML = """
<html><body>
  <form action="/login.php" method="post">
    <input type="hidden" name="user_token" value="abc123">
    <input type="text" name="username">
    <input type="password" name="password">
    <input type="submit" name="Login" value="Login">
  </form>
</body></html>
"""

# an ordinary page for a logged in user that happens to have password boxes on
# it. this is the shape that fooled the first version.
CHANGE_PASSWORD_HTML = """
<html><body>
  <a href="logout.php">Logout</a>
  <form method="post">
    <input type="password" name="password_current">
    <input type="password" name="password_new">
    <input type="submit" value="Change">
  </form>
</body></html>
"""


def page(body, url="http://127.0.0.1:8080/somewhere", status=200, headers=None):
    return Response(url=url, method="GET", status=status,
                    headers=headers or {}, body=body, elapsed_ms=1.0)


def logged_in_auth(marker="logout.php"):
    auth = FormLogin(f"{DVWA}/login.php", "admin", "password")
    auth.logged_in_at_least_once = True
    auth.marker = marker
    return auth


def test_a_password_box_is_what_marks_a_login_page():
    assert _looks_like_a_login_page(LOGIN_HTML)
    assert not _looks_like_a_login_page("<html><body><p>hello</p></body></html>")
    assert not _looks_like_a_login_page("")


def test_reading_the_form_picks_up_the_hidden_token():
    """The csrf token is why the form has to be read instead of guessed at."""
    auth = FormLogin(f"{DVWA}/login.php", "admin", "password")
    action, fields = auth._read_form(LOGIN_HTML)

    assert action == "/login.php"
    assert fields["user_token"] == "abc123"
    assert "username" in fields and "password" in fields
    # the submit button counts, some apps check for it and drop the login
    # without ever saying why
    assert fields["Login"] == "Login"


def test_the_marker_is_taken_from_the_site():
    assert FormLogin._find_marker(CHANGE_PASSWORD_HTML) == "logout.php"
    assert FormLogin._find_marker("<html><body>nothing here</body></html>") is None


def test_a_password_box_alone_does_not_mean_logged_out():
    """The regression this whole marker business exists for.

    Change your password, brute force and captcha are all normal authenticated
    pages carrying a password box. Reading those as 'logged out' made a DVWA
    crawl log back in three times for nothing and cost 15 wasted requests.
    """
    auth = logged_in_auth()
    assert not auth.looks_logged_out(page(CHANGE_PASSWORD_HTML))


def test_the_real_login_page_does_mean_logged_out():
    auth = logged_in_auth()
    assert auth.looks_logged_out(page(LOGIN_HTML))


def test_a_redirect_to_the_login_page_means_logged_out():
    auth = logged_in_auth()
    bounced = page("", status=302, headers={"location": "/login.php"})
    assert auth.looks_logged_out(bounced)


def test_asking_for_the_login_page_is_not_being_logged_out():
    auth = logged_in_auth()
    assert not auth.looks_logged_out(page(LOGIN_HTML, url=f"{DVWA}/login.php"))


def test_nothing_is_logged_out_before_we_have_logged_in():
    auth = FormLogin(f"{DVWA}/login.php", "admin", "password")
    assert not auth.looks_logged_out(page(LOGIN_HTML))


def test_scope_avoids_logout_links():
    scope = Scope.from_url(DVWA)
    assert scope.should_avoid(f"{DVWA}/logout.php")
    assert scope.should_avoid(f"{DVWA}/account/sign-out")
    assert not scope.should_avoid(f"{DVWA}/vulnerabilities/sqli/")


def test_a_redirect_cannot_walk_us_off_the_target():
    """Scope is checked on every hop, not just the first.

    httpx would follow redirects internally and the scope check would only ever
    see the url we asked for, so one redirect could put us on a host nobody gave
    us permission to touch.
    """
    scope = Scope.from_url(DVWA)
    with HttpClient(scope) as client:
        offsite = page("", status=302, headers={"location": "http://example.com/"})
        with pytest.raises(OutOfScopeError):
            client._follow(offsite, "GET", {})


# ---------------------------------------------------------------- live DVWA

@pytest.fixture(scope="module")
def dvwa_up():
    scope = Scope.from_url(DVWA)
    with HttpClient(scope) as client:
        try:
            client.get(DVWA)
        except Exception:
            pytest.skip("dvwa not running, start it with docker compose")
    return True


def test_login_to_dvwa_works(dvwa_up):
    scope = Scope.from_url(DVWA)
    auth = FormLogin(f"{DVWA}/login.php", "admin", "password")
    with HttpClient(scope, auth=auth) as client:
        assert auth.login(client)
        assert auth.marker, "should have picked up a logged in marker"


def test_a_wrong_password_is_reported_as_a_failure(dvwa_up):
    """A login that quietly fails is worse than no login at all. The scan runs,
    finds nothing behind the login, and calls the site clean."""
    scope = Scope.from_url(DVWA)
    auth = FormLogin(f"{DVWA}/login.php", "admin", "definitely-not-the-password")
    with HttpClient(scope, auth=auth) as client:
        assert not auth.login(client)


def test_logging_in_is_what_makes_dvwa_visible(dvwa_up):
    """The before and after, as a test. This is why the auth work exists.

    Anonymously the crawler gets bounced to the login page and stops there. It
    does find input fields, but every one of them is on the login form itself,
    which is not the application. Everything DVWA is actually for sits behind
    the login and may as well not exist.
    """
    scope = Scope.from_url(DVWA)

    with HttpClient(scope) as client:
        blind = Crawler(client, scope).crawl(DVWA)

    assert blind.pages == [f"{DVWA}/login.php"], \
        "anonymously the crawl should get to the login page and go no further"
    assert all("/login.php" in p.url for p in blind.injection_points), \
        "anonymously every input found should be on the login form itself"

    auth = FormLogin(f"{DVWA}/login.php", "admin", "password")
    with HttpClient(scope, auth=auth) as client:
        assert auth.login(client)
        seeing = Crawler(client, scope).crawl(DVWA)

    assert len(seeing.pages) > 20
    assert len(seeing.injection_points) > 20
    assert any("/vulnerabilities/" in p.url for p in seeing.injection_points), \
        "logged in, the crawl should reach the pages behind the login"


def test_the_crawler_does_not_log_itself_out(dvwa_up):
    scope = Scope.from_url(DVWA)
    auth = FormLogin(f"{DVWA}/login.php", "admin", "password")

    with HttpClient(scope, auth=auth) as client:
        assert auth.login(client)
        result = Crawler(client, scope).crawl(DVWA)

        assert any("logout" in url for url in result.avoided), \
            "logout.php should have been seen and deliberately skipped"
        assert not any("logout" in url for url in result.pages), \
            "the crawler requested the logout page and killed its own session"
        assert client.session_recoveries == 0, \
            "session should never have dropped during a clean crawl"
