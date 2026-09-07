"""Ties the stages together: crawl, detect, then validate."""
from .crawler import Crawler
from .detectors import sqli
from .findings import Verdict
from .validators import sqli_boolean, sqli_timing


class ScanReport:
    def __init__(self, crawl, findings, candidates):
        self.crawl = crawl
        self.findings = findings
        self.candidates = candidates

    def by_verdict(self, verdict):
        return [f for f in self.findings if f.verdict is verdict]

    @property
    def confirmed(self):
        return self.by_verdict(Verdict.CONFIRMED)

    @property
    def unconfirmed(self):
        return self.by_verdict(Verdict.UNCONFIRMED)

    @property
    def rejected(self):
        return self.by_verdict(Verdict.REJECTED)


def scan(client, scope, start_url):
    crawl = Crawler(client, scope).crawl(start_url)

    findings = []
    candidates = 0

    for point in crawl.injection_points:
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

    return ScanReport(crawl, findings, candidates)
