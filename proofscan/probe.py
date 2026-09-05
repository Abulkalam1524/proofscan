"""Helpers for sending one test value into one injection point."""
import difflib
import html


def send(client, point, value):
    """Send a request with `value` in the point's parameter, others unchanged."""
    params = point.base_params()
    params[point.param] = value
    if point.method == "POST":
        return client.post(point.url, data=params)
    return client.get(point.url, params=params)


def strip_payload(body, payload):
    """Take the payload back out of a response.

    Pages often echo what you sent. If we compare two responses without doing
    this, they differ just because the payloads differ, and every reflected
    parameter looks injectable. Escaped copies get removed too.
    """
    for form in (payload, html.escape(payload), html.escape(payload, quote=False)):
        body = body.replace(form, "@@")
    return body


def similarity(a, b):
    """0.0 to 1.0. 1.0 means the two responses are the same."""
    return difflib.SequenceMatcher(None, a, b).quick_ratio()
