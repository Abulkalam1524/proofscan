"""Web interface tests.

Three things matter here. The page has to show what the scanner proved and
nothing else, so its numbers and proofs come from the same places the pdf's do.
It has to refuse targets that are not on this machine, because a text box is an
easier way to scan something without permission than a command line is. And it
must never render a payload as html, because it displays working cross site
scripting payloads on purpose.

No server, no browser, no target needed. Flask's test client drives the app
directly against a throwaway evidence file.
"""
from pathlib import Path

import pytest

from proofscan.report import proof_rows
from proofscan.store import EvidenceStore
from samples import browser_confirmed, report, timing_confirmed
from web import app as web_app
from web.app import create_app, is_local

TEMPLATE = Path(__file__).parent.parent / "web" / "templates" / "index.html"


@pytest.fixture
def db(tmp_path):
    path = tmp_path / "evidence.db"
    with EvidenceStore(path) as store:
        store.save(report())
    return path


@pytest.fixture
def client(db):
    return create_app(db_path=db).test_client()


# --- only local targets -------------------------------------------------------

@pytest.mark.parametrize("url", [
    "http://127.0.0.1:5001",
    "http://localhost:8080/login.php",
    "http://[::1]:5001",
    "http://dvwa.test",
    "http://app.localhost:3000",
    "http://host.docker.internal:5001",
])
def test_loopback_targets_are_local(url):
    assert is_local(url)


@pytest.mark.parametrize("url", [
    "https://example.com",
    "http://8.8.8.8",
    # a private address is still somebody's machine on the network
    "http://10.0.0.5:8080",
    "http://192.168.1.20",
    "not a url",
    "",
])
def test_anything_else_is_not(url):
    assert not is_local(url)


def test_a_remote_target_is_refused_with_the_reason(client):
    response = client.post("/api/scan", json={"target": "https://example.com"})

    assert response.status_code == 403
    assert "IT Act 2000" in response.get_json()["error"]


def test_a_bare_domain_is_refused_too(client):
    """Typed without a scheme, the way somebody would type it in a hurry."""
    assert client.post("/api/scan", json={"target": "google.com"}).status_code == 403


def test_an_empty_target_is_a_clear_error(client):
    response = client.post("/api/scan", json={"target": "  "})

    assert response.status_code == 400
    assert response.get_json()["error"]


def test_allow_any_lifts_the_restriction(db, monkeypatch):
    """Deliberately, for a target there is written permission to test. The scan
    itself is stubbed out, this is only about whether the request is accepted."""
    monkeypatch.setattr(web_app, "_run", lambda *args: None)
    client = create_app(db_path=db, allow_any=True).test_client()

    response = client.post("/api/scan", json={"target": "https://example.com"})

    assert response.status_code == 200
    assert response.get_json()["state"] == "running"


def test_a_local_scan_starts_and_can_be_polled(client, monkeypatch):
    monkeypatch.setattr(web_app, "_run", lambda *args: None)

    started = client.post("/api/scan", json={"target": "127.0.0.1:5001"}).get_json()

    # the scheme is added for you
    assert started["target"] == "http://127.0.0.1:5001"
    polled = client.get(f"/api/job/{started['id']}").get_json()
    assert polled["state"] == "running"
    assert polled["requests"] == 0


def test_polling_a_job_that_does_not_exist_is_a_404(client):
    assert client.get("/api/job/nope").status_code == 404


# --- replaying stored scans ---------------------------------------------------

def test_the_page_loads(client):
    response = client.get("/")

    assert response.status_code == 200
    assert b"ProofScan" in response.data
    assert b"Replay a saved scan" in response.data


def test_stored_scans_are_listed_for_replay(client):
    scans = client.get("/api/scans").get_json()

    assert len(scans) == 1
    assert scans[0]["confirmed"] == 3
    assert scans[0]["rejected"] == 1


def test_newest_scan_comes_first(db):
    with EvidenceStore(db) as store:
        newest = store.save(report())

    scans = create_app(db_path=db).test_client().get("/api/scans").get_json()
    assert scans[0]["id"] == newest


def test_a_replayed_scan_carries_the_funnel_and_every_verdict(client):
    scan = client.get("/api/scan/1").get_json()

    assert scan["tally"]["candidates"] == 4
    assert scan["tally"]["blind"] == 1
    assert len(scan["confirmed"]) == 3
    assert len(scan["rejected"]) == 1
    assert len(scan["unconfirmed"]) == 1


def test_proved_findings_come_back_worst_first(client):
    scores = [f["score"]["cvss"] for f in client.get("/api/scan/1").get_json()["confirmed"]]

    assert scores == sorted(scores, reverse=True)


def test_the_proof_on_screen_is_the_proof_in_the_pdf(client):
    """Same helper, same sentences. The screen cannot disagree with the
    document somebody is handed afterwards."""
    shown = client.get("/api/scan/1").get_json()["confirmed"]
    timing = next(f for f in shown if f["technique"] == "timing")

    expected = [list(row) for row in proof_rows(timing_confirmed())]
    assert timing["proof"] == expected


def test_a_thrown_out_finding_says_why_and_what_was_tried(client):
    thrown_out = client.get("/api/scan/1").get_json()["rejected"][0]

    assert thrown_out["verdict"] == "REJECTED"
    assert thrown_out["detector_reason"]
    assert "noise" in thrown_out["reason"]
    assert thrown_out["attempts"]
    assert thrown_out["score"] is None


def test_unproved_findings_carry_no_score(client):
    scan = client.get("/api/scan/1").get_json()

    for f in scan["rejected"] + scan["unconfirmed"]:
        assert f["score"] is None


def test_a_scan_that_is_not_there_is_a_404(client):
    assert client.get("/api/scan/99").status_code == 404


def test_the_payload_reaches_the_page_as_data(client):
    """It goes out as a json string. Whether it is then rendered as text or as
    html is the template's job, checked below."""
    with EvidenceStore(client.application.config["DB_PATH"]) as store:
        scan_id = store.save(report([browser_confirmed()]))

    proof = dict(client.get(f"/api/scan/{scan_id}").get_json()["confirmed"][0]["proof"])
    assert proof["Payload"].startswith("<script>")


# --- the page must never run what it displays ---------------------------------

def test_the_page_never_uses_innerhtml():
    """The page shows working xss payloads, so data goes in with textContent.

    innerHTML anywhere in the template is a hole, even one that looks safe
    today, because the next person to touch it will copy it. This is the same
    rule the pdf report gets from jinja2's autoescape, enforced by hand because
    this page builds its content in javascript.
    """
    source = TEMPLATE.read_text(encoding="utf-8")

    assert "innerHTML" not in source
    assert "outerHTML" not in source
    assert "insertAdjacentHTML" not in source
    assert "document.write" not in source
    assert "textContent" in source


def test_the_page_loads_nothing_from_the_internet():
    """It has to work in an exam room with no network."""
    source = TEMPLATE.read_text(encoding="utf-8")

    assert "http://" not in source.replace("http://127.0.0.1:5001", "")
    assert "https://" not in source
    assert "<link" not in source


# --- screenshots --------------------------------------------------------------

def test_a_screenshot_is_served_as_a_png(client):
    with EvidenceStore(client.application.config["DB_PATH"]) as store:
        finding = browser_confirmed()
        finding.screenshots = [{"label": "the red box", "png": b"\x89PNG fake"}]
        scan_id = store.save(report([finding]))

    shots = client.get(f"/api/scan/{scan_id}").get_json()["confirmed"][0]["screenshots"]
    assert [s["label"] for s in shots] == ["the red box"]

    response = client.get(f"/api/shot/{shots[0]['id']}")
    assert response.mimetype == "image/png"
    assert response.data == b"\x89PNG fake"


def test_a_screenshot_that_is_not_there_is_a_404(client):
    assert client.get("/api/shot/999").status_code == 404


# --- the static showcase ------------------------------------------------------

def test_the_showcase_page_cannot_scan():
    """The replay-only copy must have no scan panel and no live server calls."""
    page = create_app().jinja_env.get_template("index.html").render(showcase=True)

    assert 'id="scan"' not in page
    assert "/api/" not in page
    assert "data/scans.json" in page


def test_the_live_page_still_scans():
    page = create_app().jinja_env.get_template("index.html").render(allow_any=False)

    assert 'id="scan"' in page
    assert '"/api/scans"' in page
