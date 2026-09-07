"""Sample findings and scans, shaped the way the validators really write them.

Shared by the store tests and the report tests, so there is one definition of
what a finding looks like rather than two that can drift apart. The evidence
dicts here are copied from real output: if the shape changes, these are what
should fail first.
"""
from datetime import datetime, timedelta, timezone

from proofscan.crawler import CrawlResult, InjectionPoint
from proofscan.findings import Finding, Verdict
from proofscan.scanner import ScanReport
from proofscan.scoring import score_finding

LAB = "http://127.0.0.1:5001"
STARTED = datetime(2026, 9, 7, 10, 0, tzinfo=timezone.utc)


def point(url, param, method="GET", source="query", other=(), value=""):
    return InjectionPoint(url=url, method=method, param=param, source=source,
                          other_params=other, value=value)


def boolean_confirmed(url=f"{LAB}/product", param="id"):
    """A true/false proof, shaped the way sqli_boolean actually writes one."""
    return Finding(
        kind="sqli",
        point=point(url, param, value="1"),
        verdict=Verdict.CONFIRMED,
        reason="true and false conditions gave different responses, twice",
        evidence={
            "detector_reason": "sqlite error text in the response",
            "technique": "boolean",
            "proof": {
                "true_payload": "1' AND '1'='1",
                "false_payload": "1' AND '1'='2",
                "true_status": 200,
                "false_status": 200,
                "true_length": 4210,
                "false_length": 3980,
                "similarity": 0.9012,
                "repeat_similarity": 0.9008,
                "noise_floor": 1.0,
                "threshold": 0.9995,
            },
            "true_body": "<html>one row</html>",
            "false_body": "<html>no rows</html>",
        },
        score=score_finding("sqli", needed_login=False),
    )


def timing_confirmed(url=f"{LAB}/blind-product", param="id"):
    """The blind case. detector_reason is None because stage 1 never saw it."""
    return Finding(
        kind="sqli",
        point=point(url, param, value="1"),
        verdict=Verdict.CONFIRMED,
        reason="the true payload slept and the false one did not, 20 times",
        evidence={
            "detector_reason": None,
            "technique": "timing",
            "proof": {
                "true_payload": "1' OR (SELECT sleep(2)) AND '1'='1",
                "false_payload": "1' OR (SELECT sleep(2)) AND '1'='2",
                "samples": 20,
                "true_median_ms": 10120.4,
                "false_median_ms": 119.0,
                "true_min_ms": 10001.2,
                "false_max_ms": 130.9,
                "median_gap_ms": 10001.4,
                "delay_asked_ms": 2000,
                "ranges_separated": True,
                "true_ms": [10001.2, 10120.4, 10233.9],
                "false_ms": [98.1, 119.0, 130.9],
            },
        },
        score=score_finding("sqli", needed_login=False),
    )


def browser_confirmed(url=f"{LAB}/search", param="q"):
    return Finding(
        kind="xss",
        point=point(url, param, method="POST", source="form",
                    other=(("csrf", "abc"), ("submit", "Submit"))),
        verdict=Verdict.CONFIRMED,
        reason="the script ran in chromium",
        evidence={
            "detector_reason": "the input came back in the page unescaped",
            "technique": "browser",
            "proof": {
                "payload": "<script>window.__proofscan_xss='t0ken'</script>",
                "token": "t0ken",
                "variable": "__proofscan_xss",
                "read_back": "t0ken",
            },
            "attempts": [{"payload": "<svg onload=...>", "result": "nothing ran"}],
        },
        score=score_finding("xss", needed_login=False),
    )


def rejected(url=f"{LAB}/safe-product", param="id"):
    return Finding(
        kind="sqli",
        point=point(url, param),
        verdict=Verdict.REJECTED,
        reason="no true/false pair beat the page's own noise (floor 0.9991)",
        evidence={
            "detector_reason": "the input came back in the page",
            "technique": "boolean",
            "noise_floor": 0.9991,
            "attempts": [{
                "true_payload": "1' AND '1'='1",
                "false_payload": "1' AND '1'='2",
                "similarity": 0.9999,
                "result": "no more different than the page is from itself",
            }],
        },
    )


def unconfirmed(url=f"{LAB}/comment", param="q"):
    return Finding(
        kind="xss",
        point=point(url, param),
        verdict=Verdict.UNCONFIRMED,
        reason="could not start a browser to prove it: chromium is not installed",
        evidence={"detector_reason": "the input came back", "technique": "browser"},
    )


def report(findings=None, target=LAB, **kwargs):
    findings = findings if findings is not None else [
        boolean_confirmed(), timing_confirmed(), browser_confirmed(),
        rejected(), unconfirmed(),
    ]
    crawl = CrawlResult(
        pages=[LAB, f"{LAB}/product", f"{LAB}/search"],
        injection_points=[f.point for f in findings],
        avoided=[f"{LAB}/logout"],
    )
    settings = dict(candidates=4, requests=195, session_recoveries=1,
                    authenticated=False, safe_mode=False,
                    started_at=STARTED,
                    finished_at=STARTED + timedelta(seconds=59))
    settings.update(kwargs)
    return ScanReport(target=target, crawl=crawl, findings=findings, **settings)
