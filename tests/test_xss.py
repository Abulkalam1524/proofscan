"""Checks the xss results against ANSWER_KEY in the test app.

The interesting cases here are the ones that look vulnerable and are not.
/plain reflects the payload back word for word but serves it as text/plain, so
nothing runs. /safe-search escapes it. A scanner that decides on the response
body flags both. Only the browser can tell them apart, which is the entire
argument for this stage existing.

Start the app first: python labs/vulnerable_app/app.py
"""
import sys
from pathlib import Path
from urllib.parse import urlparse

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent / "labs" / "vulnerable_app"))
from app import ANSWER_KEY  # noqa: E402

from proofscan.config import Scope             # noqa: E402
from proofscan.crawler import Crawler          # noqa: E402
from proofscan.detectors import xss            # noqa: E402
from proofscan.findings import Verdict         # noqa: E402
from proofscan.http_client import HttpClient   # noqa: E402
from proofscan.validators.xss_browser import BrowserProver, validate  # noqa: E402

BASE = "http://127.0.0.1:5001"


@pytest.fixture(scope="module")
def results():
    """Every reflected point, with the browser's verdict on it."""
    scope = Scope.from_url(BASE)
    with HttpClient(scope) as client:
        try:
            client.get(BASE)
        except Exception:
            pytest.skip("test app not running")

        crawl = Crawler(client, scope).crawl(BASE)
        candidates = [(p, r) for p, r in
                      ((p, xss.detect(client, p)) for p in crawl.injection_points) if r]

        with BrowserProver(scope) as prover:
            yield [validate(prover, point, reason) for point, reason in candidates]


def paths_of(findings):
    return {urlparse(f.point.url).path for f in findings}


def expected_xss_paths():
    return {path for path, bugs in ANSWER_KEY.items() if bugs["xss"]}


def confirmed(results):
    return [f for f in results if f.verdict is Verdict.CONFIRMED]


def rejected(results):
    return [f for f in results if f.verdict is Verdict.REJECTED]


def test_no_false_positives(results):
    """Nothing safe should ever be confirmed. This is the whole point."""
    wrong = paths_of(confirmed(results)) - expected_xss_paths()
    assert not wrong, f"confirmed xss on endpoints that are safe: {sorted(wrong)}"


def test_no_false_negatives(results):
    """Every real xss in the app should be confirmed."""
    missed = expected_xss_paths() - paths_of(confirmed(results))
    assert not missed, f"real xss the scanner missed: {sorted(missed)}"


def test_reflection_alone_is_not_enough(results):
    """/plain hands the payload straight back and is still not vulnerable.

    It serves text/plain, so the browser renders the script as words. This is
    the case that catches out anything deciding from the response body.
    """
    assert "/plain" in paths_of(rejected(results)), \
        "/plain reflects the payload and must still be rejected"


def test_escaped_reflection_is_rejected(results):
    """/safe-search reflects it too, escaped, so nothing runs."""
    assert "/safe-search" in paths_of(rejected(results))


def test_the_detector_flags_the_safe_pages_too(results):
    """Stage 1 is meant to be noisy. If it were not flagging the safe pages,
    it would be filtering, and filtering is the validator's job."""
    everything = paths_of(confirmed(results)) | paths_of(rejected(results))
    assert "/plain" in everything
    assert "/safe-search" in everything


def test_every_confirmed_finding_carries_proof(results):
    """A confirmed finding with no evidence attached is not confirmed."""
    for f in confirmed(results):
        proof = f.evidence.get("proof")
        assert proof, f"no proof stored for {f.point}"
        # the token is what makes this proof rather than a guess: it is freshly
        # generated per attempt and only this payload could have set it
        assert proof["token"] == proof["read_back"]
        assert proof["token"] in proof["payload"]


def test_attribute_context_needs_a_breakout(results):
    """/comment puts the input inside title="...", so a plain script tag is not
    enough and the payload has to escape the attribute first."""
    comment = [f for f in confirmed(results)
               if urlparse(f.point.url).path == "/comment"]
    assert comment, "/comment should be confirmed"
    assert comment[0].evidence["proof"]["payload"].startswith(('"', "'")), \
        "expected an attribute breakout payload to be the one that worked"
