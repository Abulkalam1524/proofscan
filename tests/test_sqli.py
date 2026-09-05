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

from proofscan.config import Scope           # noqa: E402
from proofscan.http_client import HttpClient  # noqa: E402
from proofscan.scanner import scan            # noqa: E402

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


def paths_of(findings):
    return {urlparse(f.point.url).path for f in findings}


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
    for f in report.confirmed:
        proof = f.evidence.get("proof")
        assert proof, f"no proof stored for {f.point}"
        assert proof["true_payload"] != proof["false_payload"]
        assert proof["similarity"] < 0.98
