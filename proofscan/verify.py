"""Verify mode: take ZAP's findings and prove or reject each one.

ZAP does the finding, ProofScan does the proving. ZAP's report only names the
page, method and input, so each alert is rebuilt into a full request by reading
the form on that page, then sent through the same validators a scan uses.
"""
from dataclasses import dataclass, field, replace
from datetime import datetime, timezone
from urllib.parse import urlparse

from bs4 import BeautifulSoup

from . import zap_report
from .crawler import Crawler, CrawlResult
from .findings import Finding, Verdict
from .scanner import ScanReport, _picture_sqli
from .scoring import score_finding
from .validators import sqli_boolean, sqli_timing, xss_browser


@dataclass
class VerifyResult:
    report: ScanReport
    alerts: int = 0                                 # ZAP alerts in SQLi and XSS
    other_classes: int = 0                          # ZAP alerts ProofScan cannot check
    skipped: list = field(default_factory=list)     # (alert, why)


def rewrite_url(url, rewrites):
    """ZAP often runs in Docker and sees the target under another name."""
    for old, new in rewrites:
        if url.startswith(old):
            return new + url[len(old):]
    return url


def site_of(url):
    p = urlparse(url)
    return f"{p.scheme}://{p.netloc}"


def point_for(client, crawler, alert, url):
    """The full injection point ZAP meant, or None.

    The form on the page comes first, because it carries every field the app
    expects. Then the query string ZAP recorded. ZAP's own attack value is
    cleared either way, so the validators start from a plain value.
    """
    page = url.split("?", 1)[0]
    try:
        response = client.get(page, follow_redirects=True)
        if "html" in response.headers.get("content-type", ""):
            soup = BeautifulSoup(response.body, "lxml")
            for p in crawler._form_points(soup, response.url):
                if (p.param == alert.param and p.method == alert.method
                        and zap_report.normalise_path(p.url) == alert.path):
                    return p
    except Exception:
        pass

    if alert.method == "GET":
        for p in Crawler._query_points(url):
            if p.param == alert.param:
                return replace(p, value="")
    return None


def zap_said(alerts):
    names = sorted({f"{a.name} ({a.risk} risk, {a.confidence} confidence)" for a in alerts})
    return "ZAP: " + "; ".join(names)


def _prove_sqli(client, scope, point, reason):
    result = sqli_boolean.validate(client, point, reason)
    if result.verdict is Verdict.CONFIRMED or scope.safe_mode:
        return result
    # blind injection leaves the page unchanged, so the true/false test cannot
    # see it. the clock can.
    timed = sqli_timing.validate(client, point, reason)
    return timed if timed.verdict is Verdict.CONFIRMED else result


def _prove_xss(client, scope, items, site):
    try:
        prover = xss_browser.BrowserProver(scope, xss_browser.cookies_from(client, site))
        prover.__enter__()
    except Exception as e:
        return [Finding("xss", point, Verdict.UNCONFIRMED,
                        f"could not start a browser to prove it: {e}",
                        {"detector_reason": reason, "technique": "browser"})
                for point, reason in items]
    try:
        return [xss_browser.validate(prover, point, reason) for point, reason in items]
    finally:
        prover.__exit__(None, None, None)


def verify_zap(client, scope, report, target, rewrites=()):
    started_at = datetime.now(timezone.utc)
    alerts = zap_report.parse(report)
    wanted = zap_report.in_scope(alerts)

    crawler = Crawler(client, scope)
    crawler.avoided = []
    groups = {}          # (kind, point) -> the ZAP alerts about it
    skipped = []

    for alert in wanted:
        url = rewrite_url(alert.uri, rewrites)
        if not scope.allows(url):
            skipped.append((alert, f"out of scope: {url}"))
            continue
        if scope.should_avoid(url):
            skipped.append((alert, "left alone on purpose, it changes the target"))
            continue
        point = point_for(client, crawler, alert, url)
        if point is None:
            skipped.append((alert, "could not rebuild the request from ZAP's report"))
            continue
        groups.setdefault((alert.kind, point), []).append(alert)

    findings = []
    xss_items = []
    for (kind, point), said in groups.items():
        reason = zap_said(said)
        if kind == "sqli":
            findings.append(_prove_sqli(client, scope, point, reason))
        else:
            xss_items.append((point, reason))
    if xss_items:
        findings += _prove_xss(client, scope, xss_items, target)

    _picture_sqli(client, scope, findings, target)

    needed_login = client.auth is not None
    for f in findings:
        f.evidence["source"] = "zap"
        if f.verdict is Verdict.CONFIRMED:
            f.score = score_finding(f.kind, needed_login)

    points = [point for _, point in groups]
    result = ScanReport(
        target=target,
        crawl=CrawlResult(sorted({p.url for p in points}), points, crawler.avoided),
        findings=findings,
        candidates=len(groups),
        started_at=started_at,
        finished_at=datetime.now(timezone.utc),
        requests=client.request_count,
        session_recoveries=client.session_recoveries,
        authenticated=needed_login,
        safe_mode=scope.safe_mode,
    )
    return VerifyResult(result, alerts=len(wanted),
                        other_classes=len(zap_report.out_of_scope(alerts)),
                        skipped=skipped)
