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

# Same five places as PAYLOADS, same order. Used once, after a proof has
# worked, to get a picture: the script draws a red box on the page saying what
# it is, so the screenshot shows the injected code running rather than us
# drawing on the page. {js} has no spaces or quotes, so it fits in the
# attribute cases too.
SHOW_PAYLOADS = [
    "<script>{js}</script>",
    '"><script>{js}</script>',
    "'><script>{js}</script>",
    "<img src=x onerror={js}>",
    '" onfocus={js} autofocus x="',
]

PAGE_TIMEOUT_MS = 15000
VIEWPORT = {"width": 1024, "height": 640}


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


def _js_text(text):
    # every character that is not a letter or digit becomes an escape, so the
    # string survives whatever html context it lands in
    return "".join(c if c.isascii() and c.isalnum() else "\\u%04x" % ord(c) for c in text)


def show_js(token, param):
    box = (
        '<div style="position:fixed;top:0;left:0;right:0;z-index:2147483647;'
        'background:#b00020;color:#fff;font:bold 20px/1.5 Arial,sans-serif;'
        'padding:14px 20px">'
        f'ProofScan: this red box was drawn by the script typed into the '
        f'&quot;{html.escape(param)}&quot; box. The browser ran it. ({token})</div>'
    )
    return (f"window.{PROOF_VAR}=`{token}`;"
            f"(document.body||document.documentElement)"
            f".insertAdjacentHTML(`beforeend`,`{_js_text(box)}`)")


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
        self._context = self._browser.new_context(viewport=VIEWPORT)
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

    def ran(self, point, payload, token, shot=False):
        """Load the payload and ask the browser whether the script ran.

        With shot=True the page is also screenshotted, into last_shot.
        """
        self.last_shot = None
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
            if shot:
                # the onfocus payload fires a moment after load
                try:
                    page.wait_for_function(f"window.{PROOF_VAR} === '{token}'", timeout=2000)
                except Exception:
                    pass
                self.last_shot = _screenshot(page)
            return page.evaluate(f"window.{PROOF_VAR} || null") == token
        finally:
            try:
                page.close()
            except Exception:
                pass

    def render(self, url, response):
        """Show a response we already have, as a browser would, and screenshot it.

        Used for the sql injection pictures. The browser is handed the body the
        http client got for that url, so the picture is of the evidence and not
        of a fresh request. Css and images still load from the target, but only
        in scope.
        """
        if not self.scope.allows(url):
            raise OutOfScopeError(f"out of scope: {url}")
        served = []

        def route(r):
            if r.request.is_navigation_request() and not served:
                served.append(1)
                r.fulfill(status=response.status or 200, body=response.body,
                          content_type=_content_type(response))
            elif self.scope.allows(r.request.url):
                r.continue_()
            else:
                r.abort()

        page = self._context.new_page()
        page.on("dialog", lambda d: d.dismiss())
        try:
            page.route("**/*", route)
            page.goto(url, timeout=PAGE_TIMEOUT_MS, wait_until="load")
            return _screenshot(page)
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


def _screenshot(page):
    # cut to the content, so a short page is not a picture of mostly white
    try:
        height = page.evaluate("document.body ? document.body.scrollHeight : 0")
        height = max(160, min(VIEWPORT["height"], height + 24))
        return page.screenshot(type="png", clip={"x": 0, "y": 0,
                                                 "width": VIEWPORT["width"], "height": height})
    except Exception:
        return None


def _content_type(response):
    headers = {k.lower(): v for k, v in (response.headers or {}).items()}
    return headers.get("content-type", "text/html")


def picture_of_run(prover, point, index):
    """Once a payload is proved, send the visible version and screenshot it.

    Only kept if the box's own token comes back, so a picture is never of a
    page where nothing ran. Failing to get one never changes the verdict.
    """
    token = "pf" + secrets.token_hex(8)
    payload = SHOW_PAYLOADS[index].format(js=show_js(token, point.param))
    try:
        ran = prover.ran(point, payload, token, shot=True)
    except OutOfScopeError:
        raise
    except Exception:
        return None
    if not ran or not prover.last_shot:
        return None
    return {"label": "The injected script ran and drew the red box",
            "png": prover.last_shot}


def validate(prover, point, reason):
    attempts = []
    first_shot = None

    for index, template in enumerate(PAYLOADS):
        token = "pf" + secrets.token_hex(8)
        payload = template.format(var=PROOF_VAR, token=token)

        try:
            executed = prover.ran(point, payload, token, shot=index == 0)
            if index == 0:
                first_shot = prover.last_shot
        except OutOfScopeError:
            raise
        except Exception as e:
            attempts.append({"payload": payload, "result": f"could not load: {e}"})
            continue

        if executed:
            shot = picture_of_run(prover, point, index)
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
                screenshots=[shot] if shot else [],
            )

        attempts.append({"payload": payload, "result": "loaded, but nothing ran"})

    shots = []
    if first_shot:
        shots.append({"label": "How the browser showed the page with the first "
                               "payload in it. Nothing ran.",
                      "png": first_shot})
    return Finding("xss", point, Verdict.REJECTED,
                   f"input comes back, but none of the {len(PAYLOADS)} payloads "
                   f"executed in a browser",
                   {"detector_reason": reason, "technique": "browser",
                    "attempts": attempts},
                   screenshots=shots)
