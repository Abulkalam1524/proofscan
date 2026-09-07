"""Ties the stages together: crawl, detect, then validate."""
from .crawler import Crawler
from .detectors import sqli, xss
from .findings import Finding, Verdict
from .scoring import score_finding
from .validators import sqli_boolean, sqli_timing, xss_browser


class ScanReport:
    def __init__(self, crawl, findings, candidates):
        self.crawl = crawl
        self.findings = findings
        self.candidates = candidates

    def by_verdict(self, verdict):
        return [f for f in self.findings if f.verdict is verdict]

    @property
    def confirmed(self):
        """Worst first, because that is the order somebody fixes them in."""
        return sorted(self.by_verdict(Verdict.CONFIRMED),
                      key=lambda f: (-(f.score.cvss_score if f.score else 0.0),
                                     f.point.url, f.point.param))

    @property
    def unconfirmed(self):
        return self.by_verdict(Verdict.UNCONFIRMED)

    @property
    def rejected(self):
        return self.by_verdict(Verdict.REJECTED)


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

    return ScanReport(crawl, findings, sqli_candidates + xss_candidates)
