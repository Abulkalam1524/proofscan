"""The web interface. One page: scan a target, or replay one already stored.

This exists because the people who have to understand this project read a screen
better than they read a terminal. The argument the whole thing rests on, that a
scanner should prove a finding rather than report a suspicion, is much easier to
see as a green PROVED next to a grey THROWN OUT than as lines of text scrolling
past.

**Replaying a stored scan is the main path, not an afterthought.** A live scan
takes a minute on the lab target and nearly three on DVWA, most of it the timing
validator waiting on purpose, and it needs the target up, Docker started and
Chromium installed. None of that is safe to rely on in a room on somebody else's
schedule. Replay reads the evidence file and needs nothing running at all, so
there is always something to show. That is the evidence store earning its keep a
second time.

Nothing new is detected here. Every number and every proof on the page comes
from the scanner, the store and the same `proof_rows` the pdf report uses, so
the screen cannot disagree with the document.

**The target has to be local.** Scanning a host nobody gave permission for is an
offence under the IT Act 2000, and a text box on a web page is a much easier way
to do that by accident than a command line is. So anything that is not loopback
is refused, and `--allow-any` has to be passed deliberately to lift it.
"""
import threading
import time
import uuid
from dataclasses import dataclass, field
from ipaddress import ip_address
from urllib.parse import urlparse

from flask import Flask, Response, abort, jsonify, render_template, request, send_file

from proofscan.config import Scope
from proofscan.http_client import HttpClient
from proofscan.report import attempt_rows, proof_rows, write_pdf
from proofscan.scanner import scan as run_scan
from proofscan.store import DEFAULT_PATH, EvidenceStore

LOCAL_NAMES = {"localhost", "host.docker.internal"}


def is_local(url):
    """Loopback only, unless the operator deliberately said otherwise."""
    host = (urlparse(url).hostname or "").lower()
    if not host:
        return False
    if host in LOCAL_NAMES or host.endswith((".localhost", ".test")):
        return True
    try:
        return ip_address(host).is_loopback
    except ValueError:
        return False


@dataclass
class Job:
    """One live scan, running on a thread so the page stays responsive."""
    id: str
    target: str
    state: str = "running"          # running | done | failed
    started_at: float = field(default_factory=time.time)
    client: object = None           # polled for the live request count
    scan_id: int = None
    error: str = ""

    @property
    def elapsed(self):
        return time.time() - self.started_at

    @property
    def requests(self):
        # the client counts requests as it sends them, so progress is real
        # rather than a bar that moves on a timer
        return self.client.request_count if self.client else 0

    def as_json(self):
        return {
            "id": self.id, "target": self.target, "state": self.state,
            "elapsed": round(self.elapsed, 1), "requests": self.requests,
            "scan_id": self.scan_id, "error": self.error,
        }


def finding_json(finding):
    """One finding, shaped for the page.

    The proof comes out of the same helpers the pdf uses, so what is on screen
    and what is in the document are the same sentences.
    """
    point, score = finding.point, finding.score
    return {
        "kind": finding.kind,
        "verdict": finding.verdict.value,
        "method": point.method,
        "url": point.url,
        "param": point.param,
        "source": point.source,
        "reason": finding.reason,
        "detector_reason": finding.evidence.get("detector_reason"),
        "technique": finding.evidence.get("technique"),
        "proof": proof_rows(finding),
        "attempts": attempt_rows(finding),
        # just the ids, the pictures themselves come from /api/shot
        "screenshots": [{"id": s["id"], "label": s["label"]}
                        for s in finding.screenshots if "id" in s],
        "score": None if not score else {
            "cvss": score.cvss_score,
            "severity": score.severity,
            "cwe": score.cwe,
            "owasp": score.owasp,
            "vector": score.cvss_vector,
            "not_proved": score.conventional,
        },
    }


def scan_json(stored):
    tally = stored.tally
    return {
        "id": stored.id,
        "target": stored.target,
        "started_at": stored.started_at,
        "duration": round(stored.duration_seconds),
        "pages": stored.pages,
        "injection_points": stored.injection_points,
        "requests": stored.requests,
        "authenticated": stored.authenticated,
        "safe_mode": stored.safe_mode,
        "tally": tally,
        "confirmed": [finding_json(f) for f in stored.confirmed],
        "rejected": [finding_json(f) for f in stored.rejected],
        "unconfirmed": [finding_json(f) for f in stored.unconfirmed],
    }


def create_app(db_path=DEFAULT_PATH, allow_any=False):
    app = Flask(__name__)
    app.config["DB_PATH"] = str(db_path)
    app.config["ALLOW_ANY"] = allow_any
    jobs = {}

    def store():
        return EvidenceStore(app.config["DB_PATH"])

    @app.get("/")
    def index():
        return render_template("index.html", allow_any=app.config["ALLOW_ANY"])

    @app.get("/api/scans")
    def list_scans():
        """Everything already proved and stored. This is what the demo replays."""
        with store() as s:
            return jsonify([
                {"id": row.id, "target": row.target,
                 "started_at": row.started_at,
                 "duration": round(row.duration_seconds),
                 "confirmed": row.confirmed_count,
                 "rejected": row.rejected_count,
                 "safe_mode": row.safe_mode,
                 "authenticated": row.authenticated}
                for row in reversed(s.scans())
            ])

    @app.get("/api/scan/<int:scan_id>")
    def get_scan(scan_id):
        with store() as s:
            try:
                return jsonify(scan_json(s.load(scan_id)))
            except KeyError:
                abort(404, f"no scan {scan_id} in the evidence file")

    @app.get("/api/shot/<int:shot_id>")
    def get_shot(shot_id):
        with store() as s:
            png = s.screenshot(shot_id)
        if png is None:
            abort(404, "no such screenshot")
        return Response(png, mimetype="image/png")

    @app.post("/api/scan")
    def start_scan():
        target = (request.json or {}).get("target", "").strip()
        if not target:
            return jsonify({"error": "give me a url to scan"}), 400
        if not target.startswith(("http://", "https://")):
            target = "http://" + target

        if not app.config["ALLOW_ANY"] and not is_local(target):
            return jsonify({"error":
                "This interface only scans local targets. Scanning a host "
                "without permission is an offence under the IT Act 2000. "
                "Start it with --allow-any if you have written authorisation "
                "for this target."}), 403

        safe_mode = bool((request.json or {}).get("safe_mode"))
        job = Job(id=uuid.uuid4().hex[:8], target=target)
        jobs[job.id] = job

        threading.Thread(target=_run, args=(app, job, safe_mode),
                         daemon=True).start()
        return jsonify(job.as_json())

    @app.get("/api/job/<job_id>")
    def job_status(job_id):
        job = jobs.get(job_id)
        if job is None:
            abort(404, "no such scan")
        return jsonify(job.as_json())

    @app.get("/api/report/<int:scan_id>")
    def report(scan_id):
        """The same pdf the cli writes, generated on demand."""
        with store() as s:
            try:
                stored = s.load(scan_id)
            except KeyError:
                abort(404, f"no scan {scan_id}")
        path, _ = write_pdf(stored)
        return send_file(path.resolve(), as_attachment=True)

    return app


def _run(app, job, safe_mode):
    """A whole scan, on its own thread, saved to the evidence file at the end."""
    try:
        scope = Scope.from_url(job.target, safe_mode=safe_mode)
        with HttpClient(scope) as client:
            job.client = client
            report = run_scan(client, scope, job.target)

        with EvidenceStore(app.config["DB_PATH"]) as s:
            job.scan_id = s.save(report)
        job.state = "done"
    except Exception as e:
        # the page has to say what went wrong. a scan that fails silently in a
        # demo is worse than one that fails loudly.
        job.state = "failed"
        job.error = f"{type(e).__name__}: {e}"
