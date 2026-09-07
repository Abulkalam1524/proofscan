"""Checks the sqli results against ANSWER_KEY in the test app.

This is the accuracy check. The test app publishes what is actually wrong with
it, so we can count false positives and false negatives instead of eyeballing
the output. Start the app first: python labs/vulnerable_app/app.py
"""
import sys
from pathlib import Path
from urllib.parse import urlparse

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent / "labs" / "vulnerable_app"))
from app import ANSWER_KEY  # noqa: E402

from proofscan.config import Scope             # noqa: E402
from proofscan.findings import Verdict         # noqa: E402
from proofscan.http_client import HttpClient   # noqa: E402
from proofscan.scanner import scan             # noqa: E402
from proofscan.validators import sqli_boolean  # noqa: E402

BASE = "http://127.0.0.1:5001"


@pytest.fixture(scope="module")
def report():
    scope = Scope.from_url(BASE)
    with HttpClient(scope) as client:
        try:
            client.get(BASE)
        except Exception:
            pytest.skip("test app not running")
        yield scan(client, scope, BASE)


def sqli_only(findings):
    """The report carries xss findings as well now, and these tests are not
    about those."""
    return [f for f in findings if f.kind == "sqli"]


def paths_of(findings):
    return {urlparse(f.point.url).path for f in sqli_only(findings)}


def expected_sqli_paths():
    return {path for path, bugs in ANSWER_KEY.items() if bugs["sqli"]}


def test_no_false_positives(report):
    """Nothing safe should ever be confirmed. This is the whole point."""
    wrong = paths_of(report.confirmed) - expected_sqli_paths()
    assert not wrong, f"confirmed endpoints that are actually safe: {sorted(wrong)}"


def test_no_false_negatives(report):
    """Every real sqli in the app should be confirmed."""
    missed = expected_sqli_paths() - paths_of(report.confirmed)
    assert not missed, f"real sqli the scanner missed: {sorted(missed)}"


def test_validator_rejects_the_planted_traps(report):
    """/safe-product and /jitter fool the detector, so the validator must reject them."""
    rejected = paths_of(report.rejected)
    assert "/safe-product" in rejected
    assert "/jitter" in rejected


def test_every_confirmed_finding_carries_proof(report):
    """A confirmed finding with no evidence attached is not confirmed."""
    for f in sqli_only(report.confirmed):
        proof = f.evidence.get("proof")
        assert proof, f"no proof stored for {f.point}"
        assert proof["true_payload"] != proof["false_payload"]

        if f.evidence["technique"] == "timing":
            assert proof["ranges_separated"]
            assert proof["median_gap_ms"] >= proof["delay_asked_ms"] * 0.8
        else:
            # the bar is the page's own noise, not a number picked in advance,
            # and the difference had to show up twice
            assert proof["similarity"] < proof["threshold"]
            assert proof["repeat_similarity"] < proof["threshold"]


def test_the_blind_endpoint_is_proved_by_the_clock(report):
    """/blind-product hands back the same page whatever the query does, so the
    timing test has to be the one that proves it."""
    blind = [f for f in sqli_only(report.confirmed)
             if urlparse(f.point.url).path == "/blind-product"]

    assert blind, "the timing test missed /blind-product"
    assert blind[0].evidence["technique"] == "timing"


def test_the_true_false_test_alone_would_have_missed_it(report):
    """Why there are two validators and not one.

    Run the true/false test against /blind-product on its own. It has no choice
    but to reject, because both responses really are identical. Without the
    timing test that is where a real sql injection would have been written off
    as a false alarm.
    """
    point = next(p for p in report.crawl.injection_points
                 if urlparse(p.url).path == "/blind-product")

    scope = Scope.from_url(BASE)
    with HttpClient(scope) as client:
        alone = sqli_boolean.validate(client, point, "asking the true/false test directly")

    assert alone.verdict is Verdict.REJECTED
