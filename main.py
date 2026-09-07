"""ProofScan cli.

    python main.py crawl http://127.0.0.1:5001
    python main.py scan  http://127.0.0.1:5001

Behind a login:

    set PROOFSCAN_PASSWORD=password
    python main.py scan http://127.0.0.1:8080 --login-url http://127.0.0.1:8080/login.php --username admin
"""
import argparse
import os
import sys

from proofscan.auth import FormLogin
from proofscan.config import Scope
from proofscan.crawler import Crawler
from proofscan.http_client import HttpClient
from proofscan.scanner import scan


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

        print(f"Crawled {report.crawl.summary()}")
        print(f"Detector flagged {report.candidates} of them as suspicious\n")

        print("CONFIRMED (proved, goes in the report)")
        for f in report.confirmed:
            print(f"  {f.point}")
            print(f"      {f.reason}")
            p = f.evidence["proof"]
            if f.evidence.get("technique") == "timing":
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
                print(f"  {f.point}\n      {f.reason}")

        print("\nREJECTED (false alarms, removed)")
        for f in report.rejected:
            print(f"  {f.point}")
            print(f"      detector said: {f.evidence.get('detector_reason')}")
            print(f"      but: {f.reason}")
        if not report.rejected:
            print("  none")

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
        print(f"{client.request_count} requests sent")
        if client.session_recoveries:
            print(f"session expired and was restored {client.session_recoveries} time(s)")
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
    add_login_args(sc)
    sc.set_defaults(func=cmd_scan)

    args = parser.parse_args()
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
