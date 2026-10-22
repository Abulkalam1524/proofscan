"""Stage 1 for XSS: does our input come back in the page? Noisy on purpose.

Reflection is not execution, the browser decides that in stage 2. Which
characters came back unescaped goes in the evidence.
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
    """The characters right after our marker, so only our own reflection counts."""
    at = body.find(marker)
    if at == -1:
        return ""
    return body[at + len(marker): at + len(marker) + span]
