"""ProofScan cli.

    python main.py crawl http://127.0.0.1:5001
"""
import argparse
import sys

from proofscan.config import Scope
from proofscan.crawler import Crawler
from proofscan.http_client import HttpClient


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


def main():
    parser = argparse.ArgumentParser(prog="proofscan")
    sub = parser.add_subparsers(dest="command", required=True)

    crawl = sub.add_parser("crawl", help="map a site and list its input points")
    crawl.add_argument("url")
    crawl.add_argument("--rate", type=float, default=10.0)
    crawl.add_argument("--max-pages", type=int, default=200)
    crawl.set_defaults(func=cmd_crawl)

    args = parser.parse_args()
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
