"""The evidence store. One sqlite file holding scans and what they proved.

Three reasons it exists, in order of how much they matter:

1. The report reads from here. Findings have to survive the process that made
   them, or printing a report means running the whole scan again.
2. Comparing one scan against the next. Did the fix work, did something come
   back, did the benchmark shift. That comparison is a result in its own right
   and it is impossible without stored scans.
3. It is the evidence half of the claim. A proved finding whose proof was
   printed to a terminal and then lost is not much better than a guess.

One findings table with the common columns, and the evidence dict as a json
column. The three proof shapes are a true/false comparison, a set of response
times, and a variable read back out of a browser, and they have almost nothing
in common with each other, so modelling all three in sql would mean three tables
of mostly empty columns for the sake of data nothing queries on. What does get
queried is kind, verdict, cvss and url, and those are real columns with indexes.
"""
import json
import sqlite3
from dataclasses import dataclass, field
from pathlib import Path

from .crawler import InjectionPoint
from .findings import Finding, FindingsView, Verdict
from .scoring import Score

SCHEMA_VERSION = 1
DEFAULT_PATH = Path("evidence") / "proofscan.db"


class SchemaMismatch(Exception):
    """The file was written by a different version of this schema."""


SCHEMA = """
CREATE TABLE IF NOT EXISTS meta (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS scans (
    id                 INTEGER PRIMARY KEY,
    target             TEXT    NOT NULL,
    started_at         TEXT    NOT NULL,
    finished_at        TEXT    NOT NULL,
    duration_seconds   REAL    NOT NULL,
    authenticated      INTEGER NOT NULL,
    safe_mode          INTEGER NOT NULL,
    requests           INTEGER NOT NULL,
    session_recoveries INTEGER NOT NULL,
    pages              INTEGER NOT NULL,
    injection_points   INTEGER NOT NULL,
    candidates         INTEGER NOT NULL,
    page_urls          TEXT    NOT NULL,
    avoided_urls       TEXT    NOT NULL
);

CREATE TABLE IF NOT EXISTS findings (
    id           INTEGER PRIMARY KEY,
    scan_id      INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    kind         TEXT    NOT NULL,
    verdict      TEXT    NOT NULL,
    reason       TEXT    NOT NULL,
    technique    TEXT,
    url          TEXT    NOT NULL,
    method       TEXT    NOT NULL,
    param        TEXT    NOT NULL,
    source       TEXT    NOT NULL,
    value        TEXT    NOT NULL,
    other_params TEXT    NOT NULL,
    cvss_score   REAL,
    cvss_vector  TEXT,
    severity     TEXT,
    cwe          TEXT,
    cwe_name     TEXT,
    owasp        TEXT,
    observed     TEXT,
    conventional TEXT,
    evidence     TEXT    NOT NULL
);

CREATE INDEX IF NOT EXISTS findings_by_scan  ON findings(scan_id);
CREATE INDEX IF NOT EXISTS findings_by_class ON findings(kind, verdict);
CREATE INDEX IF NOT EXISTS findings_by_cvss  ON findings(cvss_score);
CREATE INDEX IF NOT EXISTS findings_by_point ON findings(url, param);
"""

INSERT_SCAN = """
INSERT INTO scans (target, started_at, finished_at, duration_seconds,
                   authenticated, safe_mode, requests, session_recoveries,
                   pages, injection_points, candidates, page_urls, avoided_urls)
VALUES (:target, :started_at, :finished_at, :duration_seconds,
        :authenticated, :safe_mode, :requests, :session_recoveries,
        :pages, :injection_points, :candidates, :page_urls, :avoided_urls)
"""

INSERT_FINDING = """
INSERT INTO findings (scan_id, kind, verdict, reason, technique,
                      url, method, param, source, value, other_params,
                      cvss_score, cvss_vector, severity, cwe, cwe_name, owasp,
                      observed, conventional, evidence)
VALUES (:scan_id, :kind, :verdict, :reason, :technique,
        :url, :method, :param, :source, :value, :other_params,
        :cvss_score, :cvss_vector, :severity, :cwe, :cwe_name, :owasp,
        :observed, :conventional, :evidence)
"""

# verdict counts alongside each scan row, so listing scans is one query rather
# than one query per scan
LIST_SCANS = """
SELECT s.*,
       COALESCE(SUM(f.verdict = 'CONFIRMED'), 0)   AS confirmed_count,
       COALESCE(SUM(f.verdict = 'UNCONFIRMED'), 0) AS unconfirmed_count,
       COALESCE(SUM(f.verdict = 'REJECTED'), 0)    AS rejected_count
FROM scans s
LEFT JOIN findings f ON f.scan_id = s.id
GROUP BY s.id
ORDER BY s.id
"""


@dataclass
class StoredScan(FindingsView):
    """A scan read back out of the file.

    Same attribute names as ScanReport, on purpose. Anything that prints a scan
    should not have to care which of the two it was handed.
    """
    id: int
    target: str
    started_at: str
    finished_at: str
    duration_seconds: float
    authenticated: bool
    safe_mode: bool
    requests: int
    session_recoveries: int
    pages: int
    injection_points: int
    candidates: int
    page_urls: list = field(default_factory=list)
    avoided_urls: list = field(default_factory=list)
    findings: list = field(default_factory=list)

    def summary(self):
        return f"{self.pages} pages, {self.injection_points} injection points"


@dataclass
class ScanSummary:
    """One line about a stored scan, without loading its findings."""
    id: int
    target: str
    started_at: str
    duration_seconds: float
    authenticated: bool
    safe_mode: bool
    requests: int
    confirmed_count: int
    unconfirmed_count: int
    rejected_count: int


@dataclass
class Comparison:
    before: object
    after: object
    fixed: list = field(default_factory=list)         # was proved, is not now
    appeared: list = field(default_factory=list)      # is proved now, was not
    still_there: list = field(default_factory=list)   # proved both times

    @property
    def same_target(self):
        return self.before.target == self.after.target


def finding_key(finding):
    """What makes a finding in one scan the same finding as one in another.

    The place, not the proof. A fix that changes an error message must not read
    as a different bug, and a payload that worked last week and works again this
    week is the same finding rather than a new one.
    """
    point = finding.point
    return (finding.kind, point.method, point.url, point.param, point.source)


def compare(before, after):
    """Two scans of the same target, and what moved between them."""
    was = {finding_key(f): f for f in before.confirmed}
    now = {finding_key(f): f for f in after.confirmed}

    return Comparison(
        before=before,
        after=after,
        fixed=[f for key, f in was.items() if key not in now],
        appeared=[f for key, f in now.items() if key not in was],
        still_there=[f for key, f in now.items() if key in was],
    )


def _as_text(moment):
    """Timestamps go in as iso 8601, whatever they arrived as."""
    if moment is None:
        return ""
    if isinstance(moment, str):
        return moment
    return moment.isoformat(timespec="seconds")


def _as_json(value):
    """Evidence dicts hold numbers, strings and lists, and json takes all three.

    default=str is a safety net rather than a plan. If a validator ever puts
    something exotic into an evidence dict, the scan should end with a slightly
    ugly string in the file rather than with a crash after all the work is done.
    """
    return json.dumps(value, default=str)


def _finding_row(scan_id, finding):
    point = finding.point
    score = finding.score
    return {
        "scan_id": scan_id,
        "kind": finding.kind,
        "verdict": Verdict(finding.verdict).value,
        "reason": finding.reason,
        "technique": finding.evidence.get("technique"),
        "url": point.url,
        "method": point.method,
        "param": point.param,
        "source": point.source,
        "value": point.value,
        "other_params": _as_json([list(pair) for pair in point.other_params]),
        "cvss_score": score.cvss_score if score else None,
        "cvss_vector": score.cvss_vector if score else None,
        "severity": score.severity if score else None,
        "cwe": score.cwe if score else None,
        "cwe_name": score.cwe_name if score else None,
        "owasp": score.owasp if score else None,
        "observed": _as_json(score.observed) if score else None,
        "conventional": score.conventional if score else None,
        "evidence": _as_json(finding.evidence),
    }


def _finding_from_row(row):
    point = InjectionPoint(
        url=row["url"],
        method=row["method"],
        param=row["param"],
        source=row["source"],
        # back to tuples, because InjectionPoint is frozen and has to stay
        # hashable. json only knows about lists.
        other_params=tuple(tuple(pair) for pair in json.loads(row["other_params"])),
        value=row["value"],
    )

    score = None
    if row["cvss_vector"]:
        score = Score(
            cvss_vector=row["cvss_vector"],
            cvss_score=row["cvss_score"],
            severity=row["severity"],
            cwe=row["cwe"],
            cwe_name=row["cwe_name"],
            owasp=row["owasp"],
            observed=json.loads(row["observed"]) if row["observed"] else {},
            conventional=row["conventional"] or "",
        )

    return Finding(
        kind=row["kind"],
        point=point,
        verdict=Verdict(row["verdict"]),
        reason=row["reason"],
        evidence=json.loads(row["evidence"]),
        score=score,
    )


def _scan_from_row(row, findings):
    return StoredScan(
        id=row["id"],
        target=row["target"],
        started_at=row["started_at"],
        finished_at=row["finished_at"],
        duration_seconds=row["duration_seconds"],
        authenticated=bool(row["authenticated"]),
        safe_mode=bool(row["safe_mode"]),
        requests=row["requests"],
        session_recoveries=row["session_recoveries"],
        pages=row["pages"],
        injection_points=row["injection_points"],
        candidates=row["candidates"],
        page_urls=json.loads(row["page_urls"]),
        avoided_urls=json.loads(row["avoided_urls"]),
        findings=findings,
    )


class EvidenceStore:
    def __init__(self, path=DEFAULT_PATH):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(self.path)
        self.conn.row_factory = sqlite3.Row
        # sqlite ignores foreign keys unless told not to, once per connection.
        # without this, deleting a scan would leave its findings behind.
        self.conn.execute("PRAGMA foreign_keys = ON")
        self._prepare()

    def _prepare(self):
        self.conn.executescript(SCHEMA)

        row = self.conn.execute(
            "SELECT value FROM meta WHERE key = 'schema_version'").fetchone()

        if row is None:
            with self.conn:
                self.conn.execute(
                    "INSERT INTO meta (key, value) VALUES ('schema_version', ?)",
                    (str(SCHEMA_VERSION),))
        elif int(row["value"]) != SCHEMA_VERSION:
            # old scans are kept rather than migrated. a stored scan is
            # evidence, and quietly rewriting evidence to fit a newer schema is
            # the sort of thing this project exists to argue against.
            raise SchemaMismatch(
                f"{self.path} was written by schema version {row['value']}, "
                f"this is version {SCHEMA_VERSION}. Point --db at a new file "
                f"rather than mixing the two.")

    def save(self, report):
        """Store one scan and its findings, and return the new scan id.

        Both inserts run inside one transaction. Half a scan in the file is
        worse than no scan at all, because then the summary at the top quotes
        numbers that the findings underneath it do not add up to.
        """
        with self.conn:
            cursor = self.conn.execute(INSERT_SCAN, {
                "target": report.target,
                "started_at": _as_text(report.started_at),
                "finished_at": _as_text(report.finished_at),
                "duration_seconds": report.duration_seconds,
                "authenticated": int(report.authenticated),
                "safe_mode": int(report.safe_mode),
                "requests": report.requests,
                "session_recoveries": report.session_recoveries,
                "pages": report.pages,
                "injection_points": report.injection_points,
                "candidates": report.candidates,
                "page_urls": _as_json(report.page_urls),
                "avoided_urls": _as_json(report.avoided_urls),
            })
            scan_id = cursor.lastrowid

            self.conn.executemany(
                INSERT_FINDING,
                [_finding_row(scan_id, f) for f in report.findings])

        return scan_id

    def load(self, scan_id):
        """One stored scan, findings and all."""
        row = self.conn.execute(
            "SELECT * FROM scans WHERE id = ?", (scan_id,)).fetchone()
        if row is None:
            raise KeyError(f"no scan {scan_id} in {self.path}")

        findings = [_finding_from_row(r) for r in self.conn.execute(
            "SELECT * FROM findings WHERE scan_id = ? ORDER BY id", (scan_id,))]

        return _scan_from_row(row, findings)

    def scans(self):
        """Every stored scan, oldest first, with verdict counts but no findings."""
        return [
            ScanSummary(
                id=row["id"],
                target=row["target"],
                started_at=row["started_at"],
                duration_seconds=row["duration_seconds"],
                authenticated=bool(row["authenticated"]),
                safe_mode=bool(row["safe_mode"]),
                requests=row["requests"],
                confirmed_count=row["confirmed_count"],
                unconfirmed_count=row["unconfirmed_count"],
                rejected_count=row["rejected_count"],
            )
            for row in self.conn.execute(LIST_SCANS)
        ]

    def latest(self, target=None):
        """The most recent scan, of a given target or of anything. None if empty."""
        sql = "SELECT id FROM scans"
        params = ()
        if target is not None:
            sql += " WHERE target = ?"
            params = (target,)
        sql += " ORDER BY id DESC LIMIT 1"

        row = self.conn.execute(sql, params).fetchone()
        return None if row is None else self.load(row["id"])

    def query(self, kind=None, verdict=None, min_cvss=None, url_like=None,
              scan_id=None):
        """Findings across every stored scan, filtered. Returns (scan_id, finding).

        This is what the plain columns beside the json blob are for. "Has this
        parameter ever come back confirmed, and in which scan" is a question
        about four columns, and it is one the report asks.
        """
        clauses = []
        params = {}

        if kind is not None:
            clauses.append("kind = :kind")
            params["kind"] = kind
        if verdict is not None:
            clauses.append("verdict = :verdict")
            params["verdict"] = Verdict(verdict).value
        if min_cvss is not None:
            clauses.append("cvss_score >= :min_cvss")
            params["min_cvss"] = min_cvss
        if url_like is not None:
            clauses.append("url LIKE :url_like")
            params["url_like"] = f"%{url_like}%"
        if scan_id is not None:
            clauses.append("scan_id = :scan_id")
            params["scan_id"] = scan_id

        sql = "SELECT * FROM findings"
        if clauses:
            sql += " WHERE " + " AND ".join(clauses)
        sql += " ORDER BY scan_id, id"

        return [(row["scan_id"], _finding_from_row(row))
                for row in self.conn.execute(sql, params)]

    def close(self):
        self.conn.close()

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()
