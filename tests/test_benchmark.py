"""Benchmark harness tests.

The scoring is tested on a made up ZAP report rather than against a live scan,
for the same reason the timing statistics are: a real run cannot be made to
produce the awkward cases on demand, and the awkward cases are the ones that
decide whether the numbers in the dissertation are right.

The awkward cases here are a tool reporting a documented trap, a tool missing a
real bug, and a tool reporting something the answer key has never heard of.
Every one of those has to land in the right bucket, because these counts are the
result the project is judged on.

No server needed, no ZAP needed.
"""
import json

import pytest

from benchmark import answer_keys, compare, zap_report
from benchmark.answer_keys import DVWA
from proofscan.crawler import CrawlResult, InjectionPoint
from proofscan.findings import Finding, Verdict
from proofscan.scanner import ScanReport
from proofscan.scoring import score_finding

DVWA_URL = "http://127.0.0.1:8080"


def zap_alert(name, cwe, instances, riskcode="3", confidence="2"):
    return {
        "pluginid": "0", "alertRef": "0", "alert": name, "name": name,
        "riskcode": riskcode, "confidence": confidence, "cweid": cwe,
        "wascid": "19", "desc": "", "solution": "",
        "count": str(len(instances)),
        "instances": instances,
    }


def instance(path, param, method="GET"):
    return {"uri": f"{DVWA_URL}{path}", "method": method, "param": param,
            "attack": "' OR '1'='1", "evidence": ""}


# A plausible ZAP active scan of DVWA. Two real sql injections found, the md5
# password trap flagged, three cross site scripting findings including the DOM
# one ProofScan cannot see, the CSP trap flagged, and three alerts from classes
# outside the comparison.
ZAP_REPORT = {
    "@version": "2.15.0",
    "site": [{
        "@name": DVWA_URL,
        "alerts": [
            zap_alert("SQL Injection", "89", [
                instance("/vulnerabilities/sqli/", "id"),
                instance("/vulnerabilities/brute/", "username"),
                instance("/vulnerabilities/brute/", "password"),
            ]),
            # a second sql rule covering a url the first one already covered
            zap_alert("SQL Injection - MySQL", "89", [
                instance("/vulnerabilities/sqli/", "id"),
            ]),
            zap_alert("Cross Site Scripting (Reflected)", "79", [
                instance("/vulnerabilities/xss_r/", "name"),
                instance("/vulnerabilities/csp/", "include"),
            ]),
            zap_alert("Cross Site Scripting (Persistent)", "79", [
                instance("/vulnerabilities/xss_s/", "mtxMessage", "POST"),
            ]),
            zap_alert("Cross Site Scripting (DOM Based)", "79", [
                instance("/vulnerabilities/xss_d/", "default"),
            ]),
            zap_alert("Missing Anti-clickjacking Header", "1021",
                      [instance("/index.php", "")], riskcode="2"),
            zap_alert("X-Content-Type-Options Header Missing", "693",
                      [instance("/index.php", "")], riskcode="1"),
            zap_alert("Absence of Anti-CSRF Tokens", "352",
                      [instance("/vulnerabilities/csrf/", "")], riskcode="1"),
        ],
    }],
}


def point(path, param, method="GET"):
    return InjectionPoint(url=f"{DVWA_URL}{path}", method=method, param=param,
                          source="query" if method == "GET" else "form")


def finding(path, param, kind, verdict, detector_reason="looked suspicious",
            method="GET"):
    evidence = {"detector_reason": detector_reason, "technique": "boolean"}
    if verdict is Verdict.CONFIRMED:
        evidence["proof"] = {"true_payload": "x", "false_payload": "y"}
    return Finding(
        kind=kind, point=point(path, param, method), verdict=verdict,
        reason="proved" if verdict is Verdict.CONFIRMED else "thrown out",
        evidence=evidence,
        score=score_finding(kind, True) if verdict is Verdict.CONFIRMED else None,
    )


@pytest.fixture
def dvwa_scan():
    """ProofScan's real DVWA result, as recorded in NOTES.md.

    Six confirmed, six rejected. The blind injection carries no detector reason
    because stage one never saw it, which is what makes the verification-off row
    honest.
    """
    findings = [
        finding("/vulnerabilities/sqli/", "id", "sqli", Verdict.CONFIRMED),
        finding("/vulnerabilities/brute/", "username", "sqli", Verdict.CONFIRMED),
        finding("/vulnerabilities/sqli_blind/", "id", "sqli", Verdict.CONFIRMED,
                detector_reason=None),
        finding("/vulnerabilities/xss_r/", "name", "xss", Verdict.CONFIRMED),
        finding("/vulnerabilities/xss_s/", "txtName", "xss", Verdict.CONFIRMED,
                method="POST"),
        finding("/vulnerabilities/xss_s/", "mtxMessage", "xss", Verdict.CONFIRMED,
                method="POST"),
        finding("/vulnerabilities/brute/", "password", "sqli", Verdict.REJECTED),
        finding("/vulnerabilities/fi/", "page", "sqli", Verdict.REJECTED),
        finding("/vulnerabilities/fi/", "page", "xss", Verdict.REJECTED),
        finding("/vulnerabilities/csp/", "include", "xss", Verdict.REJECTED),
    ]
    return ScanReport(
        target=DVWA_URL,
        crawl=CrawlResult(pages=[DVWA_URL], injection_points=[]),
        findings=findings,
        candidates=9,
        requests=364,
    )


# --- reading a zap report -----------------------------------------------------

def test_paths_are_reduced_to_something_both_tools_can_be_matched_on():
    """ZAP keeps the query string, ProofScan does not, and DVWA is inconsistent
    about trailing slashes."""
    assert zap_report.normalise_path(
        "http://127.0.0.1:8080/vulnerabilities/SQLi/?id=1&Submit=Submit"
    ) == "/vulnerabilities/sqli"
    assert zap_report.normalise_path("http://127.0.0.1:8080/") == "/"


def test_every_instance_becomes_its_own_alert():
    """One ZAP rule covering three parameters is three things to check."""
    alerts = zap_report.parse(json.dumps(ZAP_REPORT))
    sqli = [a for a in alerts if a.kind == "sqli"]

    assert {a.param for a in sqli} == {"id", "username", "password"}


def test_two_rules_finding_the_same_thing_count_once():
    """Otherwise ZAP is charged twice for one alert a person checks once, which
    would flatter ProofScan.

    Both rules are kept when reading the report, because which rules fired is
    worth knowing. They collapse to one place to check at scoring time.
    """
    alerts = zap_report.parse(json.dumps(ZAP_REPORT))
    on_id = [a for a in alerts if a.kind == "sqli" and a.param == "id"]

    assert len(on_id) == 2
    assert {a.name for a in on_id} == {"SQL Injection", "SQL Injection - MySQL"}

    scored = compare.score("zap", compare.from_zap(on_id), DVWA)
    assert len(scored.reported) == 1
    assert len(scored.hits) == 1


def test_the_class_comes_from_the_cwe_not_the_rule_name():
    """ZAP has several names for sql injection and they change between releases.
    CWE-89 does not."""
    alerts = {a.name: a.kind for a in zap_report.parse(json.dumps(ZAP_REPORT))}

    assert alerts["SQL Injection - MySQL"] == "sqli"
    assert alerts["Cross Site Scripting (DOM Based)"] == "xss"
    assert alerts["Absence of Anti-CSRF Tokens"] is None


def test_alerts_outside_the_two_classes_are_kept_and_counted():
    """Not dropped. ZAP covering more ground is a real difference and hiding it
    would be dishonest in ProofScan's favour."""
    alerts = zap_report.parse(json.dumps(ZAP_REPORT))

    assert len(zap_report.out_of_scope(alerts)) == 3
    # eight raw instances in the two classes, which are seven distinct places
    # once the two sql rules that both hit /sqli [id] are folded together
    assert len(zap_report.in_scope(alerts)) == 8
    assert len({a.key for a in zap_report.in_scope(alerts)}) == 7


def test_a_report_can_be_read_from_a_file(tmp_path):
    path = tmp_path / "zap.json"
    path.write_text(json.dumps(ZAP_REPORT), encoding="utf-8")

    assert len(zap_report.parse(path)) == len(
        zap_report.parse(json.dumps(ZAP_REPORT)))


def test_an_empty_report_is_not_a_crash():
    assert zap_report.parse('{"site": []}') == []


# --- scoring against the answer key -------------------------------------------

def test_the_answer_key_is_not_importable_from_the_scanner():
    """Nothing being measured should be able to see the answers."""
    import proofscan
    assert not hasattr(proofscan, "answer_keys")
    assert answer_keys.DVWA.name == "DVWA"


def test_the_dvwa_key_says_what_is_real_and_what_is_a_trap():
    assert len(DVWA.real) == 7
    assert len(DVWA.traps) == 2
    assert {e.param for e in DVWA.traps} == {"password", "include"}


def test_a_correct_report_scores_a_hit():
    result = compare.score("t", [
        compare.Reported("sqli", "/vulnerabilities/sqli", "id"),
    ], DVWA)

    assert len(result.hits) == 1
    assert result.false_alarms == []


def test_reporting_a_documented_trap_is_a_false_alarm():
    """The md5 password field and the CSP page are the two that separate a
    scanner that checks from one that guesses."""
    result = compare.score("t", [
        compare.Reported("sqli", "/vulnerabilities/brute", "password"),
        compare.Reported("xss", "/vulnerabilities/csp", "include"),
    ], DVWA)

    assert len(result.traps) == 2
    assert result.hits == []
    assert result.precision == 0.0


def test_reporting_something_the_key_has_never_heard_of_is_also_a_false_alarm():
    """And it is kept apart, because an answer key written by a person is never
    complete and those need checking by hand."""
    result = compare.score("t", [
        compare.Reported("sqli", "/vulnerabilities/exec", "ip"),
    ], DVWA)

    assert len(result.unlisted) == 1
    assert len(result.false_alarms) == 1
    assert result.traps == []


def test_missing_a_real_bug_counts_against_recall():
    result = compare.score("t", [
        compare.Reported("xss", "/vulnerabilities/xss_r", "name"),
    ], DVWA)

    assert len(result.missed) == 6
    assert result.recall == pytest.approx(1 / 7)
    assert result.precision == 1.0


def test_the_same_thing_reported_twice_counts_once():
    result = compare.score("t", [
        compare.Reported("sqli", "/vulnerabilities/sqli", "id"),
        compare.Reported("sqli", "/vulnerabilities/sqli", "id"),
    ], DVWA)

    assert len(result.reported) == 1
    assert len(result.hits) == 1


def test_a_tool_that_reports_nothing_scores_zero_rather_than_dividing_by_zero():
    result = compare.score("t", [], DVWA)

    assert result.precision == 0.0
    assert result.recall == 0.0
    assert result.f1 == 0.0


# --- the three rows -----------------------------------------------------------

def test_verification_off_is_what_stage_one_alone_would_report(dvwa_scan):
    reported = {r.key for r in compare.from_detector(dvwa_scan)}

    # the trap and the out-of-class noise are in there, because the detector
    # flagged them and nothing has thrown them out yet
    assert ("sqli", "/vulnerabilities/brute", "password") in reported
    assert ("xss", "/vulnerabilities/csp", "include") in reported
    # and the blind injection is not, because stage one never saw it
    assert ("sqli", "/vulnerabilities/sqli_blind", "id") not in reported


def test_verification_on_is_only_what_was_proved(dvwa_scan):
    reported = {r.key for r in compare.from_confirmed(dvwa_scan)}

    assert ("sqli", "/vulnerabilities/sqli_blind", "id") in reported
    assert ("sqli", "/vulnerabilities/brute", "password") not in reported
    assert len(reported) == 6


def test_the_comparison_has_the_three_rows_and_the_numbers(dvwa_scan):
    alerts = zap_report.parse(json.dumps(ZAP_REPORT))
    result = compare.run(dvwa_scan, alerts, DVWA)

    off = result.tool("ProofScan, verification off")
    on = result.tool("ProofScan, verification on")
    zap = result.tool("OWASP ZAP")

    # verification turns four false alarms into none without losing a hit
    assert len(off.false_alarms) == 4
    assert len(on.false_alarms) == 0
    assert len(on.hits) == 6

    # and it finds one stage one could not see at all
    assert len(on.hits) > len(off.hits)
    assert on.precision == 1.0

    # ZAP finds the DOM based one ProofScan cannot, and flags both traps
    assert len(zap.hits) == 5
    assert len(zap.traps) == 2
    assert ("xss", "/vulnerabilities/xss_d", "default") in {e.key for e in zap.hits}
    assert ("xss", "/vulnerabilities/xss_d", "default") in {e.key for e in on.missed}


def test_zaps_wider_coverage_is_reported_beside_the_table(dvwa_scan):
    alerts = zap_report.parse(json.dumps(ZAP_REPORT))
    result = compare.run(dvwa_scan, alerts, DVWA)

    assert result.zap_other_classes == 3
    assert "3 further alerts" in compare.format_table(result)


def test_the_table_prints_every_row_with_its_precision(dvwa_scan):
    alerts = zap_report.parse(json.dumps(ZAP_REPORT))
    table = compare.format_table(compare.run(dvwa_scan, alerts, DVWA))

    assert "ProofScan, verification off" in table
    assert "ProofScan, verification on" in table
    assert "OWASP ZAP" in table
    assert "1.00" in table


def test_the_matrix_shows_what_each_tool_said_about_each_entry(dvwa_scan):
    """The table is the result. This is what somebody checks it against."""
    alerts = zap_report.parse(json.dumps(ZAP_REPORT))
    matrix = compare.format_matrix(compare.run(dvwa_scan, alerts, DVWA))

    assert "/vulnerabilities/xss_d [default]" in matrix
    assert "REAL" in matrix and "trap" in matrix
    assert "stage 1" in matrix and "verified" in matrix and "ZAP" in matrix

    # the DOM based one: real, missed by both ProofScan columns, found by ZAP
    row = next(line for line in matrix.splitlines() if "xss_d" in line)
    assert row.split()[-3:] == [".", ".", "yes"]


def test_an_unknown_answer_key_says_which_ones_exist():
    with pytest.raises(KeyError, match="dvwa"):
        answer_keys.get("juiceshop")
