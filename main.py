"""ProofScan cli.

    python main.py crawl http://127.0.0.1:5001
    python main.py scan  http://127.0.0.1:5001
"""
import argparse
import sys

from proofscan.config import Scope
from proofscan.crawler import Crawler
from proofscan.http_client import HttpClient
from proofscan.scanner import scan


def cmd_crawl(args):
    scope = Scope.from_url(args.url, requests_per_second=args.rate,
                           max_pages=args.max_pages)
    print(f"Target : {args.url}")
    print(f"Scope  : {', '.join(sorted(scope.allowed_hosts))}")
    print(f"Limits : {scope.requests_per_second}/s, max {scope.max_pages} pages\n")

    with HttpClient(scope) as client:
        result = Crawler(client, scope).crawl(args.url)

        print(f"Pages found ({len(result.pages)}):")
        for url in result.pages:
            print(f"  {url}")

        print(f"\nInjection points ({len(result.injection_points)}):")
        for point in result.injection_points:
            print(f"  {point}")

        print(f"\n{result.summary()} in {client.request_count} requests")
    return 0


def cmd_scan(args):
    scope = Scope.from_url(args.url, requests_per_second=args.rate,
                           max_pages=args.max_pages)
    print(f"Target : {args.url}\n")

    with HttpClient(scope) as client:
        report = scan(client, scope, args.url)

        print(f"Crawled {report.crawl.summary()}")
        print(f"Detector flagged {report.candidates} of them as suspicious\n")

        print("CONFIRMED (proved, goes in the report)")
        for f in report.confirmed:
            print(f"  {f.point}")
            print(f"      {f.reason}")
            p = f.evidence["proof"]
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
            print(f"      detector said: {f.evidence['detector_reason']}")
            print(f"      but: {f.reason}")
        if not report.rejected:
            print("  none")

        removed = len(report.rejected)
        pct = (removed / report.candidates * 100) if report.candidates else 0
        print(f"\n{report.candidates} suspicious -> {len(report.confirmed)} proved, "
              f"{removed} false alarms removed ({pct:.0f}%)")
        print(f"{client.request_count} requests sent")
    return 0


def main():
    parser = argparse.ArgumentParser(prog="proofscan")
    sub = parser.add_subparsers(dest="command", required=True)

    crawl = sub.add_parser("crawl", help="map a site and list its input points")
    crawl.add_argument("url")
    crawl.add_argument("--rate", type=float, default=10.0)
    crawl.add_argument("--max-pages", type=int, default=200)
    crawl.set_defaults(func=cmd_crawl)

    sc = sub.add_parser("scan", help="crawl, detect and validate")
    sc.add_argument("url")
    sc.add_argument("--rate", type=float, default=10.0)
    sc.add_argument("--max-pages", type=int, default=200)
    sc.set_defaults(func=cmd_scan)

    args = parser.parse_args()
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
