"""Ground truth. What is actually wrong with each benchmark target.

A comparison between two scanners is only worth something if somebody already
knows the right answer. Otherwise "ZAP found 41 things and ProofScan found 6" is
not a result, it is two numbers.

So each target gets an answer key written by hand from the target's own
documentation and source, and both tools are scored against it the same way.
The key is deliberately kept separate from the scanner: nothing in `proofscan/`
imports this, so there is no way for the tool being measured to see the answers.

Two kinds of entry:

- `real=True`  a genuine vulnerability of that class, at that place. A tool that
               misses it has a false negative.
- `real=False` a documented trap. Something that looks like that class and is
               not one. A tool that reports it has a false positive, and these
               are the interesting ones, because they are where scanners
               normally fail.

Anything a tool reports that is not in the key at all is counted as a false
alarm and listed separately for checking by hand, because an answer key written
by a person is never complete and pretending otherwise is how benchmarks lie.
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


# DVWA at security level low. Written from DVWA's own source and its published
# description of each module, not from what ProofScan reported, which would make
# the whole exercise circular.
#
# Only SQL injection and cross site scripting appear here. DVWA also ships
# command injection, file inclusion, csrf, file upload, weak session ids and an
# open redirect. Those are real vulnerabilities and neither tool is scored on
# them, because ProofScan v1 does not look for them. They are what the "outside
# the compared classes" line in the results is for.
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


KEYS = {"dvwa": DVWA}


def get(name):
    try:
        return KEYS[name.lower()]
    except KeyError:
        raise KeyError(f"no answer key called {name!r}. "
                       f"have: {', '.join(sorted(KEYS))}") from None
