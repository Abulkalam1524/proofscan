"""Ties the stages together: crawl, detect, then validate."""
from dataclasses import dataclass, field
from datetime import datetime, timezone

from .crawler import Crawler
from .detectors import sqli, xss
from .findings import Finding, FindingsView, Verdict
from .scoring import score_finding
from .validators import sqli_boolean, sqli_timing, xss_browser


@dataclass
class ScanReport(FindingsView):
    """Everything one scan produced.

    It carries the counters off the client and the settings off the scope as
    well as the findings, rather than pointing at either. A report that has to
    ask the client how many requests it sent cannot be written once the client
    is closed, and the whole point of storing a scan is that it outlives the
    process that ran it.
    """
    target: str
    crawl: object
    findings: list = field(default_factory=list)
    candidates: int = 0
    started_at: object = None                  # datetime, utc
    finished_at: object = None
    requests: int = 0
    session_recoveries: int = 0
    authenticated: bool = False
    safe_mode: bool = False

    @property
    def duration_seconds(self):
        if self.started_at is None or self.finished_at is None:
            return 0.0
        return (self.finished_at - self.started_at).total_seconds()

    @property
    def pages(self):
        return len(self.crawl.pages)

    @property
    def injection_points(self):
        return len(self.crawl.injection_points)

    @property
    def page_urls(self):
        return list(self.crawl.pages)

    @property
    def avoided_urls(self):
        return list(self.crawl.avoided)

    def summary(self):
        return f"{self.pages} pages, {self.injection_points} injection points"


def _scan_sqli(client, scope, points):
    """Detector, then the true/false test, then the clock. Returns findings."""
    findings = []
    candidates = 0

    for point in points:
        reason = sqli.detect(client, point)

        boolean = None
        if reason is not None:
            candidates += 1
            boolean = sqli_boolean.validate(client, point, reason)
            if boolean.verdict is Verdict.CONFIRMED:
                findings.append(boolean)
                continue                  # proved already, no need to make it wait

        # the timing test does not wait to be invited by the detector. blind
        # sqli is the case where the page never changes, so there is nothing for
        # stage 1 to notice and nothing for the true/false test to compare. if
        # we only ran this on points the detector flagged we would never see it.
        if scope.safe_mode:
            if boolean is not None:
                findings.append(boolean)
            continue

        timed = sqli_timing.validate(client, point, reason)
        if timed.verdict is Verdict.CONFIRMED:
            findings.append(timed)
        elif boolean is not None:
            findings.append(boolean)      # keep the verdict that had a reason behind it
        # detector saw nothing and the clock saw nothing, so there is nothing to report

    return findings, candidates


def _scan_xss(client, scope, points, base_url):
    """Find reflected input, then let a browser decide whether it runs."""
    candidates = [(p, r) for p, r in ((p, xss.detect(client, p)) for p in points) if r]
    if not candidates:
        return [], 0

    try:
        prover_cm = xss_browser.BrowserProver(scope, xss_browser.cookies_from(client, base_url))
        prover_cm.__enter__()
    except Exception as e:
        # no browser, no proof. say so rather than guessing from the response,
        # because guessing from the response is the thing this stage exists to
        # stop doing.
        return [
            Finding("xss", point, Verdict.UNCONFIRMED,
                    f"could not start a browser to prove it: {e}",
                    {"detector_reason": reason, "technique": "browser"})
            for point, reason in candidates
        ], len(candidates)

    try:
        return ([xss_browser.validate(prover_cm, point, reason)
                 for point, reason in candidates],
                len(candidates))
    finally:
        prover_cm.__exit__(None, None, None)


def scan(client, scope, start_url):
    started_at = datetime.now(timezone.utc)

    crawl = Crawler(client, scope).crawl(start_url)

    sqli_findings, sqli_candidates = _scan_sqli(client, scope, crawl.injection_points)
    xss_findings, xss_candidates = _scan_xss(client, scope, crawl.injection_points,
                                             start_url)

    findings = sqli_findings + xss_findings

    # Score what was proved, and only what was proved. Privileges required comes
    # from whether the scan needed credentials to get here, which is the one
    # cvss metric this tool can actually observe rather than assume.
    needed_login = client.auth is not None
    for finding in findings:
        if finding.verdict is Verdict.CONFIRMED:
            finding.score = score_finding(finding.kind, needed_login)

    return ScanReport(
        target=start_url,
        crawl=crawl,
        findings=findings,
        candidates=sqli_candidates + xss_candidates,
        started_at=started_at,
        finished_at=datetime.now(timezone.utc),
        requests=client.request_count,
        session_recoveries=client.session_recoveries,
        authenticated=needed_login,
        safe_mode=scope.safe_mode,
    )
