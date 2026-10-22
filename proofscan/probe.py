"""Helpers for sending one test value into one injection point."""
import difflib
import html


def send(client, point, value, **kwargs):
    """Send value in the point's parameter, others unchanged. Extra kwargs go to the client."""
    params = point.base_params()
    params[point.param] = value
    if point.method == "POST":
        return client.post(point.url, data=params, **kwargs)
    return client.get(point.url, params=params, **kwargs)


def strip_payload(body, payload):
    """Take the payload, and its escaped forms, back out of a response before comparing."""
    for form in (payload, html.escape(payload), html.escape(payload, quote=False)):
        body = body.replace(form, "@@")
    return body


def similarity(a, b):
    """0.0 to 1.0. 1.0 means the two responses are the same."""
    return difflib.SequenceMatcher(None, a, b).quick_ratio()
