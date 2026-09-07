"""Stage 1 for cross site scripting. Does our input come back out?

Noisy on purpose, like the sqli detector. Reflection is not a vulnerability. A
page that escapes the input properly still reflects it, and so does a page that
returns it as plain text where nothing can run. Both get flagged here, and both
get thrown out by the browser in stage 2. That split is the whole point: this
stage is cheap and generous, the next one is expensive and strict.

It also reports which characters survived the round trip. That does not decide
anything, it just goes in the evidence, because "the angle brackets came back
untouched" is the sentence that makes a report readable.
"""
import random
import string

from ..probe import send

# something that will not turn up on a page by accident, and that no escaping
# routine will alter, so it reflects identically whether the page is safe or not
MARKER_ALPHABET = string.ascii_lowercase + string.digits

# the characters that decide whether reflected input can become code
INTERESTING = ["<", ">", '"', "'"]


def _marker():
    return "px" + "".join(random.choice(MARKER_ALPHABET) for _ in range(8))


def detect(client, point):
    """Return a short reason if the input is reflected, otherwise None."""
    marker = _marker()

    plain = send(client, point, marker)
    if marker not in plain.body:
        return None

    # it comes back. now find out in what state, purely for the write up
    probe_value = f"{marker}<>\"'"
    probe = send(client, point, probe_value)
    survived = [c for c in INTERESTING if f"{marker}" in probe.body and c in _tail(probe.body, marker)]

    if survived:
        return f"input is reflected and {''.join(survived)} came back unescaped"
    return "input is reflected, but the interesting characters came back escaped"


def _tail(body, marker, span=16):
    """The few characters sitting right after the marker in the response.

    Looking at the whole page would find angle brackets everywhere, since the
    page is made of them. Only what came back attached to our own marker counts.
    """
    at = body.find(marker)
    if at == -1:
        return ""
    return body[at + len(marker): at + len(marker) + span]
