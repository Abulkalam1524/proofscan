"""Stage 1. Looks for anything that might be sql injection.

This is meant to be noisy. Missing a real bug here is much worse than flagging
something extra, because whatever it flags still has to get past the validator
before it reaches the report.
"""
from ..probe import send, similarity, strip_payload

ERROR_SIGNS = [
    "sqlite3.", "unrecognized token", "sql syntax", "syntax error",
    "you have an error in your sql", "unclosed quotation",
    "ora-0", "psycopg2", "sqlstate", "odbc driver",
]


def detect(client, point):
    """Return a short reason if the point looks injectable, otherwise None."""
    base = point.value or "1"

    baseline = send(client, point, base)
    probe = send(client, point, base + "'")

    body = probe.body.lower()
    for sign in ERROR_SIGNS:
        if sign in body:
            return f"database error in response ({sign})"

    if probe.status != baseline.status:
        return f"status changed {baseline.status} to {probe.status}"

    # compare with the payload taken back out, so a page that just echoes the
    # input does not look like it changed
    a = strip_payload(baseline.body, base)
    b = strip_payload(probe.body, base + "'")
    if similarity(a, b) < 0.98:
        return "response changed when a quote was added"

    return None
