"""What is really wrong with each benchmark target, written by hand from its docs and source.

real=True is a bug a tool should find. real=False is a trap that looks like one
and is not. Anything reported that is not in the key counts as a false alarm.
"""
from dataclasses import dataclass


@dataclass(frozen=True)
class Entry:
    path: str          # url path only, lower case, no trailing slash, no query
    param: str
    kind: str          # "sqli" or "xss"
    real: bool
    note: str = ""

    @property
    def key(self):
        return (self.kind, self.path, self.param)


@dataclass
class AnswerKey:
    name: str
    description: str
    entries: list

    @property
    def real(self):
        return [e for e in self.entries if e.real]

    @property
    def traps(self):
        return [e for e in self.entries if not e.real]

    def lookup(self, key):
        for entry in self.entries:
            if entry.key == key:
                return entry
        return None


# DVWA at security level low, written from DVWA's source and docs, not from
# what ProofScan reported. Only SQL injection and XSS are listed, because v1
# looks for nothing else.
DVWA = AnswerKey(
    name="DVWA",
    description="DVWA, ghcr.io/digininja/dvwa:latest, security level low",
    entries=[
        # --- SQL injection, real ---
        Entry("/vulnerabilities/sqli", "id", "sqli", True,
              "the id goes straight into the query, error visible in the page"),
        Entry("/vulnerabilities/sqli_blind", "id", "sqli", True,
              "injectable, but the page never changes and shows no error. only "
              "a timing test can prove this one"),
        Entry("/vulnerabilities/brute", "username", "sqli", True,
              "the login query concatenates the username, so the check can be "
              "made always true"),

        # --- SQL injection, traps ---
        Entry("/vulnerabilities/brute", "password", "sqli", False,
              "looks identical to the username field and is not injectable. "
              "DVWA runs the password through md5 before it reaches the query, "
              "so nothing an attacker types survives to the sql"),

        # --- cross site scripting, real ---
        Entry("/vulnerabilities/xss_r", "name", "xss", True,
              "reflected, echoed into the page with no escaping"),
        Entry("/vulnerabilities/xss_s", "txtName", "xss", True,
              "stored, POST, written to the guestbook and served to everyone"),
        Entry("/vulnerabilities/xss_s", "mtxMessage", "xss", True,
              "stored, POST, the message body of the same guestbook"),
        Entry("/vulnerabilities/xss_d", "default", "xss", True,
              "DOM based. the payload never appears in the server's response, "
              "it is read from location and written to the page by javascript. "
              "ProofScan cannot see this one and says so, it is a known miss "
              "rather than a surprise"),

        # --- cross site scripting, traps ---
        Entry("/vulnerabilities/csp", "include", "xss", False,
              "the payload comes back completely unescaped, so anything "
              "deciding from the response body calls this a vulnerability. It "
              "is not one: the page sends a Content-Security-Policy header and "
              "the browser refuses to run the script. Only actually running it "
              "can tell the two apart"),
    ],
)


# The lab target in labs/vulnerable_app, per parameter. Weaker evidence than
# DVWA, because the same person wrote the app and the scanner.
LAB = AnswerKey(
    name="lab",
    description="ProofScan lab target, labs/vulnerable_app, on 127.0.0.1:5001",
    entries=[
        # --- SQL injection, real ---
        Entry("/product", "id", "sqli", True,
              "the id is concatenated into the query and the sqlite error is "
              "printed on the page"),
        Entry("/blind-product", "id", "sqli", True,
              "injectable and completely silent. same page every time, no error, "
              "no missing row. the true/false test cannot prove this one and "
              "correctly rejects it, only the clock finds it"),
        Entry("/login", "username", "sqli", True,
              "concatenated into the WHERE clause"),
        Entry("/login", "password", "sqli", True,
              "concatenated into the same clause as the username"),

        # --- SQL injection, traps ---
        Entry("/safe-product", "id", "sqli", False,
              "the fixed version of /product. parameterised, but it still echoes "
              "the input, so a detector that watches for the response changing "
              "flags it"),
        Entry("/jitter", "id", "sqli", False,
              "not injectable, just slow about one request in six. a timing "
              "check that trusts a single slow response reports a bug here"),

        # --- cross site scripting, real ---
        Entry("/search", "q", "xss", True,
              "reflected into the page body with no escaping"),
        Entry("/comment", "q", "xss", True,
              "reflected inside a title attribute, so it needs breaking out of "
              "the attribute first"),
        Entry("/product", "id", "xss", True,
              "not planted. the sqlite error handler prints the error with "
              "<pre>{e}</pre>, and sqlite quotes the offending input back inside "
              "that message, so the payload arrives unescaped and runs"),

        # --- cross site scripting, traps ---
        Entry("/safe-search", "q", "xss", False,
              "the fixed version of /search, html escaped"),
        Entry("/plain", "q", "xss", False,
              "reflects the payload back word for word and is completely safe, "
              "because it serves text/plain and the browser renders the script "
              "as words. a scanner that asks only whether the input came back "
              "cannot tell this from /search"),
        Entry("/jitter", "id", "xss", False,
              "escaped on the way out"),
    ],
)

# /login may also have XSS through its sqlite error, but the app's own key
# says no and it was never confirmed, so it is left out either way.

KEYS = {"dvwa": DVWA, "lab": LAB}


def get(name):
    try:
        return KEYS[name.lower()]
    except KeyError:
        raise KeyError(f"no answer key called {name!r}. "
                       f"have: {', '.join(sorted(KEYS))}") from None
