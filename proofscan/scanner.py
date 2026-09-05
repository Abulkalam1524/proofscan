"""Ties the stages together: crawl, detect, then validate."""
from .crawler import Crawler
from .detectors import sqli
from .findings import Verdict
from .validators import sqli_boolean


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
    for point in crawl.injection_points:
        reason = sqli.detect(client, point)
        if reason is None:
            continue                      # nothing suspicious, no need to validate
        findings.append(sqli_boolean.validate(client, point, reason))

    return ScanReport(crawl, findings, candidates=len(findings))
