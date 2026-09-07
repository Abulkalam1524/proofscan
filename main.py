"""ProofScan cli.

    python main.py crawl http://127.0.0.1:5001
    python main.py scan  http://127.0.0.1:5001

Behind a login:

    set PROOFSCAN_PASSWORD=password
    python main.py scan http://127.0.0.1:8080 --login-url http://127.0.0.1:8080/login.php --username admin

Every scan is stored. Reading them back:

    python main.py scans              # what is in the file
    python main.py show 3             # one scan, printed from the file
    python main.py diff 2 3           # what moved between two scans
"""
import argparse
import os
import sys

from proofscan.auth import FormLogin
from proofscan.config import Scope
from proofscan.crawler import Crawler
from proofscan.http_client import HttpClient
from proofscan.scanner import scan
from proofscan.store import DEFAULT_PATH, EvidenceStore, compare


def add_login_args(parser):
    parser.add_argument("--login-url", help="url of the login form")
    parser.add_argument("--username", default="admin")
    parser.add_argument("--password",
                        help="prefer PROOFSCAN_PASSWORD, anything on the command "
                             "line is visible to every process on the machine")
    parser.add_argument("--username-field", default="username")
    parser.add_argument("--password-field", default="password")
    parser.add_argument("--cookie", action="append", default=[], metavar="NAME=VALUE",
                        help="send a cookie with every request, repeatable. some "
                             "apps keep state here, eg DVWA needs security=low or "
                             "it serves the fully patched build")


def add_db_arg(parser):
    parser.add_argument("--db", default=str(DEFAULT_PATH), metavar="PATH",
                        help=f"evidence file to use (default {DEFAULT_PATH})")


def build_cookies(args):
    cookies = {}
    for pair in args.cookie:
        if "=" not in pair:
            sys.exit(f"--cookie wants NAME=VALUE, got {pair!r}")
        name, value = pair.split("=", 1)
        cookies[name.strip()] = value.strip()
    return cookies


def build_auth(args):
    if not args.login_url:
        return None

    password = args.password or os.environ.get("PROOFSCAN_PASSWORD")
    if not password:
        sys.exit("--login-url was given but no password. "
                 "set PROOFSCAN_PASSWORD, or pass --password")

    return FormLogin(args.login_url, args.username, password,
                     username_field=args.username_field,
                     password_field=args.password_field)


def sign_in(client, auth):
    """Log in before anything else, and stop if it did not work.

    Carrying on after a failed login is the worst outcome available. The scan
    runs, finds nothing behind the login, and reports a clean site.
    """
    if auth is None:
        return True

    print(f"Login  : {auth}")
    if not auth.login(client):
        print("         failed, the site still shows a login form")
        return False
    print("         ok")
    return True


def print_findings(report):
    """The three verdict blocks.

    Takes a live scan report or one loaded back out of the evidence store,
    without knowing which. If the stored copy cannot produce this same output
    then the store lost something on the way in.
    """
    print("CONFIRMED (proved, goes in the report, worst first)")
    for f in report.confirmed:
        print(f"  [{f.kind}] {f.point}")
        if f.score:
            print(f"      {f.score.cvss_score} {f.score.severity}  "
                  f"{f.score.cwe}  {f.score.owasp}")
            print(f"      {f.score.cvss_vector}")
        print(f"      {f.reason}")
        p = f.evidence["proof"]
        if f.kind == "xss":
            print(f"      payload: {p['payload']}")
            print(f"      {p['variable']} came back as {p['read_back']}")
        elif f.evidence.get("technique") == "timing":
            print(f"      true : {p['true_payload']}")
            print(f"             -> {p['true_median_ms']:.0f} ms median, "
                  f"fastest {p['true_min_ms']:.0f} ms")
            print(f"      false: {p['false_payload']}")
            print(f"             -> {p['false_median_ms']:.0f} ms median, "
                  f"slowest {p['false_max_ms']:.0f} ms")
        else:
            print(f"      true : {p['true_payload']}  -> {p['true_length']} bytes")
            print(f"      false: {p['false_payload']}  -> {p['false_length']} bytes")
    if not report.confirmed:
        print("  none")

    if report.unconfirmed:
        print("\nUNCONFIRMED (could not prove either way)")
        for f in report.unconfirmed:
            print(f"  [{f.kind}] {f.point}\n      {f.reason}")

    print("\nREJECTED (false alarms, removed)")
    for f in report.rejected:
        print(f"  [{f.kind}] {f.point}")
        print(f"      detector said: {f.evidence.get('detector_reason')}")
        print(f"      but: {f.reason}")
    if not report.rejected:
        print("  none")


def print_tally(report):
    # findings the detector never flagged are the blind ones, caught by the
    # clock alone. counting them as candidates would flatter the percentage.
    from_detector = [f for f in report.confirmed if f.evidence.get("detector_reason")]
    blind = len(report.confirmed) - len(from_detector)

    removed = len(report.rejected)
    pct = (removed / report.candidates * 100) if report.candidates else 0
    print(f"\n{report.candidates} suspicious -> {len(from_detector)} proved, "
          f"{removed} false alarms removed ({pct:.0f}%)")
    if blind:
        print(f"plus {blind} the detector could not see, proved by the timing test")
    print(f"{report.requests} requests sent")
    if report.session_recoveries:
        print(f"session expired and was restored {report.session_recoveries} time(s)")


def cmd_crawl(args):
    scope = Scope.from_url(args.url, requests_per_second=args.rate,
                           max_pages=args.max_pages)
    auth = build_auth(args)
    cookies = build_cookies(args)

    print(f"Target : {args.url}")
    print(f"Scope  : {', '.join(sorted(scope.allowed_hosts))}")
    if cookies:
        print(f"Cookies: {', '.join(sorted(cookies))}")
    print(f"Limits : {scope.requests_per_second}/s, max {scope.max_pages} pages")

    with HttpClient(scope, auth=auth, cookies=cookies) as client:
        if not sign_in(client, auth):
            return 1
        print()

        result = Crawler(client, scope).crawl(args.url)

        print(f"Pages found ({len(result.pages)}):")
        for url in result.pages:
            print(f"  {url}")

        print(f"\nInjection points ({len(result.injection_points)}):")
        for point in result.injection_points:
            print(f"  {point}")

        if result.avoided:
            print(f"\nLeft alone on purpose ({len(result.avoided)}), touching "
                  f"these would change what the scan is measuring:")
            for url in result.avoided:
                print(f"  {url}")

        print(f"\n{result.summary()} in {client.request_count} requests")
        if client.session_recoveries:
            print(f"session expired and was restored {client.session_recoveries} time(s)")
    return 0


def cmd_scan(args):
    scope = Scope.from_url(args.url, requests_per_second=args.rate,
                           max_pages=args.max_pages, safe_mode=args.safe_mode)
    auth = build_auth(args)
    cookies = build_cookies(args)

    print(f"Target : {args.url}")
    if cookies:
        print(f"Cookies: {', '.join(sorted(cookies))}")
    if scope.safe_mode:
        print("Safe mode: on, the timing tests are skipped")

    with HttpClient(scope, auth=auth, cookies=cookies) as client:
        if not sign_in(client, auth):
            return 1
        print()

        report = scan(client, scope, args.url)

    # everything below comes off the report rather than the client, which is why
    # it can run out here with the connection already closed, and why the same
    # report can be written to a file and printed again next week
    print(f"Crawled {report.summary()}")
    print(f"Detector flagged {report.candidates} of them as suspicious\n")

    print_findings(report)
    print_tally(report)

    if args.no_save:
        print("\nNot saved (--no-save)")
    else:
        with EvidenceStore(args.db) as store:
            scan_id = store.save(report)
        print(f"\nSaved as scan {scan_id} in {args.db}")

    return 0


def cmd_scans(args):
    with EvidenceStore(args.db) as store:
        rows = store.scans()

    if not rows:
        print(f"No scans stored in {args.db} yet.")
        return 0

    print(f"{args.db}, {len(rows)} scan(s)\n")
    print(f"{'id':>3}  {'when (utc)':19}  {'took':>6}  {'req':>5}  "
          f"{'conf':>4} {'unc':>4} {'rej':>4}  target")
    for s in rows:
        notes = []
        if s.authenticated:
            notes.append("login")
        if s.safe_mode:
            notes.append("safe mode")
        suffix = f"  ({', '.join(notes)})" if notes else ""
        print(f"{s.id:>3}  {s.started_at[:19]:19}  {s.duration_seconds:>5.0f}s  "
              f"{s.requests:>5}  {s.confirmed_count:>4} {s.unconfirmed_count:>4} "
              f"{s.rejected_count:>4}  {s.target}{suffix}")
    return 0


def cmd_show(args):
    with EvidenceStore(args.db) as store:
        try:
            report = store.load(args.id)
        except KeyError as e:
            sys.exit(str(e))

    print(f"Scan {report.id}: {report.target}")
    print(f"Ran    : {report.started_at}, took {report.duration_seconds:.0f}s")
    settings = []
    if report.authenticated:
        settings.append("logged in")
    if report.safe_mode:
        settings.append("safe mode, timing tests skipped")
    if settings:
        print(f"Run as : {', '.join(settings)}")
    print(f"Crawled {report.summary()}")
    print(f"Detector flagged {report.candidates} of them as suspicious\n")

    print_findings(report)
    print_tally(report)

    if report.avoided_urls:
        print(f"\nLeft alone on purpose ({len(report.avoided_urls)}):")
        for url in report.avoided_urls:
            print(f"  {url}")
    return 0


def cmd_diff(args):
    with EvidenceStore(args.db) as store:
        try:
            before = store.load(args.before)
            after = store.load(args.after)
        except KeyError as e:
            sys.exit(str(e))

    result = compare(before, after)

    print(f"scan {before.id} ({before.started_at[:19]})  ->  "
          f"scan {after.id} ({after.started_at[:19]})")
    if result.same_target:
        print(f"target {before.target}")
    else:
        # not refused, because scanning the fixed copy on another port is a
        # perfectly normal thing to want to compare. said out loud, because a
        # diff across two different apps means nothing and looks like it does.
        print(f"[!] different targets: {before.target} then {after.target}. "
              f"Findings are matched by url, so almost everything will read as "
              f"fixed and new.")

    if after.safe_mode != before.safe_mode:
        print("[!] one of these ran in safe mode and the other did not, so the "
              "timing findings are not comparable")

    for title, findings in (("FIXED", result.fixed),
                            ("NEW", result.appeared),
                            ("STILL THERE", result.still_there)):
        print(f"\n{title} ({len(findings)})")
        if not findings:
            print("  none")
        for f in findings:
            score = f"{f.score.cvss_score} {f.score.severity}  " if f.score else ""
            print(f"  {score}[{f.kind}] {f.point}")

    return 0


def main():
    parser = argparse.ArgumentParser(prog="proofscan")
    sub = parser.add_subparsers(dest="command", required=True)

    crawl = sub.add_parser("crawl", help="map a site and list its input points")
    crawl.add_argument("url")
    crawl.add_argument("--rate", type=float, default=10.0)
    crawl.add_argument("--max-pages", type=int, default=200)
    add_login_args(crawl)
    crawl.set_defaults(func=cmd_crawl)

    sc = sub.add_parser("scan", help="crawl, detect and validate")
    sc.add_argument("url")
    sc.add_argument("--rate", type=float, default=10.0)
    sc.add_argument("--max-pages", type=int, default=200)
    sc.add_argument("--safe-mode", action="store_true",
                    help="skip the timing tests, the only ones that make the "
                         "server wait")
    sc.add_argument("--no-save", action="store_true",
                    help="do not write this scan to the evidence file")
    add_login_args(sc)
    add_db_arg(sc)
    sc.set_defaults(func=cmd_scan)

    scans = sub.add_parser("scans", help="list the scans in the evidence file")
    add_db_arg(scans)
    scans.set_defaults(func=cmd_scans)

    show = sub.add_parser("show", help="print one stored scan")
    show.add_argument("id", type=int)
    add_db_arg(show)
    show.set_defaults(func=cmd_show)

    diff = sub.add_parser("diff", help="compare two stored scans")
    diff.add_argument("before", type=int)
    diff.add_argument("after", type=int)
    add_db_arg(diff)
    diff.set_defaults(func=cmd_diff)

    args = parser.parse_args()
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
