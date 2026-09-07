"""Evidence store tests.

The store's whole job is that a scan survives the process that made it, so most
of what is worth testing here is a round trip: put a report in, take it back
out, and check that what comes back would print the same report as what went in.
The proofs are the part that matters. A store that keeps the verdict and loses
the numbers behind it has thrown away the evidence and kept the guess.

No server needed for any of this.
"""
from datetime import datetime, timedelta, timezone

import pytest

from proofscan.crawler import CrawlResult, InjectionPoint
from proofscan.findings import Finding, Verdict
from proofscan.scanner import ScanReport
from proofscan.scoring import score_finding
from proofscan import store as store_module
from proofscan.store import EvidenceStore, SchemaMismatch, compare, finding_key

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


@pytest.fixture
def store(tmp_path):
    with EvidenceStore(tmp_path / "evidence.db") as s:
        yield s


@pytest.fixture
def saved(store):
    """One stored scan, loaded straight back out."""
    return store.load(store.save(report()))


def test_everything_that_went_in_comes_back(saved):
    assert len(saved.findings) == 5
    assert len(saved.confirmed) == 3
    assert len(saved.rejected) == 1
    assert len(saved.unconfirmed) == 1


def test_verdicts_come_back_as_verdicts(saved):
    """Not as the strings they were stored as.

    by_verdict compares with `is`, so a finding whose verdict came back as a
    plain string would land in none of the three buckets and vanish from the
    report without anything failing.
    """
    for f in saved.findings:
        assert f.verdict is Verdict(f.verdict)
    assert saved.confirmed[0].verdict is Verdict.CONFIRMED


def test_the_proof_survives_intact(store):
    """The numbers behind a verdict, not just the verdict."""
    original = timing_confirmed()
    loaded = store.load(store.save(report([original])))

    assert loaded.findings[0].evidence == original.evidence

    proof = loaded.findings[0].evidence["proof"]
    assert proof["true_median_ms"] == 10120.4
    assert proof["true_ms"] == [10001.2, 10120.4, 10233.9]
    # a bool, not the 1 a sqlite column would have turned it into
    assert proof["ranges_separated"] is True


def test_rejected_findings_keep_what_was_tried(store):
    """The false alarm count is only believable with the attempts behind it."""
    loaded = store.load(store.save(report([rejected()])))
    evidence = loaded.rejected[0].evidence

    assert evidence["noise_floor"] == 0.9991
    assert evidence["attempts"][0]["similarity"] == 0.9999
    assert "proof" not in evidence


def test_scores_survive_and_only_proved_findings_have_one(saved):
    for f in saved.confirmed:
        assert f.score is not None
        assert f.score.cvss_vector.startswith("CVSS:3.1/")
        assert f.score.observed["PR"] == "N"
        assert f.score.conventional

    for f in saved.rejected + saved.unconfirmed:
        assert f.score is None


def test_the_injection_point_survives(store):
    original = browser_confirmed()
    loaded = store.load(store.save(report([original])))
    point_back = loaded.findings[0].point

    assert point_back == original.point
    # frozen and hashable, so other_params has to come back a tuple of tuples
    # rather than the lists json turns them into
    assert point_back.other_params == (("csrf", "abc"), ("submit", "Submit"))
    assert hash(point_back)


def test_confirmed_still_comes_back_worst_first(saved):
    scores = [f.score.cvss_score for f in saved.confirmed]
    assert scores == sorted(scores, reverse=True)
    assert scores[0] == 9.8      # sqli, no login
    assert scores[-1] == 6.1     # xss


def test_a_blind_finding_still_reads_as_blind(store):
    """detector_reason is None on a timing-only finding, and has to stay None.

    The tally line counts anything with a detector_reason as a candidate the
    detector flagged. If json turned the None into an empty string the count
    would still work, but if it turned it into the string "None" the blind
    finding would start claiming the detector saw it, which flatters the number.
    """
    loaded = store.load(store.save(report([timing_confirmed()])))
    assert loaded.confirmed[0].evidence["detector_reason"] is None


def test_the_scan_metadata_is_stored(saved):
    assert saved.target == LAB
    assert saved.requests == 195
    assert saved.session_recoveries == 1
    assert saved.candidates == 4
    assert saved.pages == 3
    assert saved.injection_points == 5
    assert saved.duration_seconds == 59.0
    assert saved.authenticated is False
    assert saved.safe_mode is False
    assert saved.avoided_urls == [f"{LAB}/logout"]
    assert saved.page_urls[0] == LAB


def test_safe_mode_and_login_are_remembered(store):
    """Two scans are not comparable unless you know how each one was run."""
    loaded = store.load(store.save(report(safe_mode=True, authenticated=True)))
    assert loaded.safe_mode is True
    assert loaded.authenticated is True


def test_duration_is_worked_out_from_real_timestamps(store):
    """The report quotes how long a scan took, so it has to be stored, not
    recomputed from two strings later."""
    loaded = store.load(store.save(report(
        started_at=STARTED, finished_at=STARTED + timedelta(seconds=165))))

    assert loaded.duration_seconds == 165.0
    assert loaded.started_at == "2026-09-07T10:00:00+00:00"


def test_scans_do_not_bleed_into_each_other(store):
    first = store.save(report([boolean_confirmed()]))
    second = store.save(report([browser_confirmed(), rejected()]))

    assert len(store.load(first).findings) == 1
    assert len(store.load(second).findings) == 2
    assert [s.id for s in store.scans()] == [first, second]


def test_the_listing_counts_verdicts(store):
    store.save(report())
    listed = store.scans()[0]

    assert listed.confirmed_count == 3
    assert listed.unconfirmed_count == 1
    assert listed.rejected_count == 1
    assert listed.requests == 195


def test_a_scan_with_no_findings_still_lists(store):
    """A clean target is a result too, and left join plus sum returns null."""
    store.save(report([]))
    listed = store.scans()[0]

    assert listed.confirmed_count == 0
    assert listed.rejected_count == 0


def test_latest_is_the_last_one_in(store):
    store.save(report(target="http://127.0.0.1:8080"))
    newest = store.save(report(target=LAB))

    assert store.latest().id == newest
    assert store.latest(target="http://127.0.0.1:8080").id == newest - 1
    assert store.latest(target="http://nothing.here") is None


def test_latest_of_an_empty_file_is_none(store):
    assert store.latest() is None


def test_loading_a_scan_that_is_not_there_raises(store):
    with pytest.raises(KeyError):
        store.load(99)


def test_findings_are_queryable_across_scans(store):
    """The columns beside the json blob, doing the job they are there for."""
    first = store.save(report())
    second = store.save(report([boolean_confirmed(), rejected()]))

    # the two sqli in the first scan, one in the second. the xss is 6.1
    high = store.query(min_cvss=9.0)
    assert [scan_id for scan_id, _ in high] == [first, first, second]
    assert {f.kind for _, f in high} == {"sqli"}

    assert len(store.query(kind="xss")) == 2
    assert len(store.query(verdict=Verdict.REJECTED)) == 2
    assert len(store.query(verdict="CONFIRMED", scan_id=second)) == 1

    # a substring match on both sides, so "product" also catches the blind and
    # the safe ones, and "/product" does not
    assert {f.point.url for _, f in store.query(url_like="product")} == {
        f"{LAB}/product", f"{LAB}/blind-product", f"{LAB}/safe-product"}
    assert {f.point.url for _, f in store.query(url_like="/product")} == {
        f"{LAB}/product"}


def test_query_returns_whole_findings_not_just_rows(store):
    store.save(report([timing_confirmed()]))
    _, finding = store.query(kind="sqli")[0]

    assert finding.evidence["proof"]["samples"] == 20
    assert finding.score.cwe == "CWE-89"


def test_half_a_scan_is_never_left_behind(store):
    """The findings insert failing must take the scan row with it.

    A scan row with no findings under it reads as a clean target, which is the
    most expensive way this could go wrong.
    """
    broken = Finding("sqli", None, Verdict.CONFIRMED, "no point on this one")

    with pytest.raises(AttributeError):
        store.save(report([boolean_confirmed(), broken]))

    assert store.scans() == []


def test_a_file_from_another_schema_is_refused(tmp_path, monkeypatch):
    """Old scans are kept rather than migrated, because they are evidence."""
    path = tmp_path / "evidence.db"
    with EvidenceStore(path) as s:
        s.save(report())

    monkeypatch.setattr(store_module, "SCHEMA_VERSION", 2)
    with pytest.raises(SchemaMismatch):
        EvidenceStore(path)


def test_reopening_a_file_keeps_what_was_in_it(tmp_path):
    path = tmp_path / "evidence.db"
    with EvidenceStore(path) as s:
        scan_id = s.save(report())

    with EvidenceStore(path) as s:
        assert len(s.load(scan_id).confirmed) == 3
        assert s.save(report()) == scan_id + 1


# --- comparing one scan against the next -------------------------------------

def test_a_fix_shows_up_as_fixed(store):
    before = store.load(store.save(report([boolean_confirmed(),
                                           browser_confirmed()])))
    after = store.load(store.save(report([browser_confirmed()])))

    result = compare(before, after)

    assert [f.point.url for f in result.fixed] == [f"{LAB}/product"]
    assert [f.point.url for f in result.still_there] == [f"{LAB}/search"]
    assert result.appeared == []


def test_something_new_shows_up_as_new(store):
    before = store.load(store.save(report([boolean_confirmed()])))
    after = store.load(store.save(report([boolean_confirmed(),
                                          timing_confirmed()])))

    result = compare(before, after)

    assert [f.point.url for f in result.appeared] == [f"{LAB}/blind-product"]
    assert result.fixed == []
    assert len(result.still_there) == 1


def test_a_bug_that_stops_being_proved_counts_as_fixed(store):
    """Rejected this time, confirmed last time, is a fix and not a disappearance."""
    before = store.load(store.save(report([boolean_confirmed()])))
    after = store.load(store.save(report([rejected(url=f"{LAB}/product")])))

    result = compare(before, after)

    assert len(result.fixed) == 1
    assert result.fixed[0].point.url == f"{LAB}/product"


def test_the_same_bug_found_a_different_way_is_not_a_new_bug(store):
    """Matched on where it is, not on how it was proved.

    The same parameter caught by the timing test one week and the true/false
    test the next is one finding that is still there, not one fixed and one new.
    """
    url = f"{LAB}/product"
    before = store.load(store.save(report([timing_confirmed(url=url)])))
    after = store.load(store.save(report([boolean_confirmed(url=url)])))

    result = compare(before, after)

    assert len(result.still_there) == 1
    assert result.fixed == []
    assert result.appeared == []


def test_comparing_two_targets_is_flagged(store):
    before = store.load(store.save(report(target=LAB)))
    after = store.load(store.save(report(target="http://127.0.0.1:8080")))

    assert compare(before, after).same_target is False
    assert compare(before, before).same_target is True


def test_findings_at_different_params_are_different_findings():
    """/login has two, and a fix to one is not a fix to the other."""
    username = Finding("sqli", point(f"{LAB}/login", "username"),
                       Verdict.CONFIRMED, "")
    password = Finding("sqli", point(f"{LAB}/login", "password"),
                       Verdict.CONFIRMED, "")

    assert finding_key(username) != finding_key(password)
