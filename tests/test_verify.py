"""Verify mode: ZAP's findings, proved or rejected by ProofScan.

The lab app has to be running for most of these: python labs/vulnerable_app/app.py
"""
import json

import pytest

from proofscan import verify
from proofscan.config import Scope
from proofscan.findings import Verdict
from proofscan.http_client import HttpClient
from proofscan.zap_report import parse

LAB = "http://127.0.0.1:5001"
DOCKER_LAB = "http://host.docker.internal:5001"
REWRITE = [(DOCKER_LAB, LAB)]


def zap_json(*alerts):
    """A minimal ZAP traditional-json report. alerts are (name, cwe, method, uri, param)."""
    return json.dumps({"site": [{"@name": DOCKER_LAB, "alerts": [
        {"name": name, "cweid": cwe, "riskcode": "3", "confidence": "2",
         "instances": [{"uri": uri, "method": method, "param": param}]}
        for name, cwe, method, uri, param in alerts]}]})


@pytest.fixture(scope="module")
def lab_up():
    with HttpClient(Scope.from_url(LAB)) as client:
        try:
            client.get(LAB)
        except Exception:
            pytest.skip("test app not running")


def run(report, safe_mode=False):
    scope = Scope.from_url(LAB, safe_mode=safe_mode)
    with HttpClient(scope) as client:
        return verify.verify_zap(client, scope, report, LAB, REWRITE)


# --- no server needed ---------------------------------------------------------

def test_rewrite_maps_the_host_zap_saw():
    assert verify.rewrite_url(f"{DOCKER_LAB}/search?q=1", REWRITE) == f"{LAB}/search?q=1"
    assert verify.rewrite_url("http://other/x", REWRITE) == "http://other/x"


def test_all_of_zaps_names_for_one_point_are_kept():
    alerts = parse(zap_json(
        ("Cross Site Scripting (Reflected)", "79", "GET", f"{DOCKER_LAB}/search?q=a", "q"),
        ("Cross Site Scripting (DOM Based)", "79", "GET", f"{DOCKER_LAB}/search?q=b", "q")))
    said = verify.zap_said(alerts)
    assert said.startswith("ZAP: ")
    assert "Reflected" in said and "DOM Based" in said


# --- against the lab app ------------------------------------------------------

def test_zaps_real_lab_findings_are_all_proved(lab_up):
    """ZAP made no false alarms on the lab, so every one should be confirmed."""
    result = run("reports/zap-lab.json")
    report = result.report

    assert result.alerts == 6
    assert report.candidates == 5          # the two /search alerts are one point
    assert len(report.confirmed) == 5
    assert not report.rejected
    for f in report.confirmed:
        assert f.evidence["source"] == "zap"
        assert f.evidence["detector_reason"].startswith("ZAP: ")


def test_zap_false_alarms_on_the_traps_are_thrown_out(lab_up):
    """The lab's traps look vulnerable and are not. Pretend ZAP reported them."""
    report = run(zap_json(
        ("Cross Site Scripting (Reflected)", "79", "GET", f"{DOCKER_LAB}/plain?q=x", "q"),
        ("Cross Site Scripting (Reflected)", "79", "GET", f"{DOCKER_LAB}/safe-search?q=x", "q"),
        ("SQL Injection", "89", "GET", f"{DOCKER_LAB}/safe-product?id=1", "id"),
    ), safe_mode=True).report

    assert report.candidates == 3
    assert not report.confirmed
    assert len(report.rejected) == 3


def test_zaps_attack_value_is_not_used_as_the_starting_value(lab_up):
    result = run(zap_json(
        ("SQL Injection", "89", "GET", f"{DOCKER_LAB}/product?id=%27+OR+1%3D1", "id")))
    point = result.report.findings[0].point
    assert point.value == ""
    assert result.report.confirmed


def test_out_of_scope_alerts_are_skipped_not_tested(lab_up):
    result = run(zap_json(
        ("SQL Injection", "89", "GET", "http://example.com/product?id=1", "id")))
    assert result.report.candidates == 0
    assert result.skipped and "out of scope" in result.skipped[0][1]
