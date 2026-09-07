"""Score a stored ProofScan scan and a ZAP report against the same answer key.

    python -m benchmark --scan 3 --zap reports/zap-dvwa.json --key dvwa

Its own entry point rather than a subcommand of main.py, so that the scanner
never imports the answers even by accident. ProofScan reads the target. This
reads ProofScan.

Both sides come out of a file. The ProofScan side is a stored scan, so the
numbers in the comparison are the numbers that were recorded at the time and
not whatever a fresh run happens to produce today.
"""
import argparse
import sys

from proofscan.store import DEFAULT_PATH, EvidenceStore

from . import answer_keys, compare, zap_report


def main():
    parser = argparse.ArgumentParser(prog="benchmark")
    parser.add_argument("--scan", type=int, required=True,
                        help="id of the stored ProofScan scan to score")
    parser.add_argument("--zap", required=True, metavar="PATH",
                        help="ZAP json report of the same target")
    parser.add_argument("--key", default="dvwa",
                        help=f"answer key to score against "
                             f"({', '.join(sorted(answer_keys.KEYS))})")
    parser.add_argument("--db", default=str(DEFAULT_PATH), metavar="PATH")
    parser.add_argument("-o", "--output", metavar="PATH",
                        help="also write the tables to a text file")
    args = parser.parse_args()

    try:
        key = answer_keys.get(args.key)
    except KeyError as e:
        sys.exit(str(e))

    with EvidenceStore(args.db) as store:
        try:
            scan = store.load(args.scan)
        except KeyError as e:
            sys.exit(str(e))

    alerts = zap_report.parse(args.zap)
    result = compare.run(scan, alerts, key)

    report = "\n\n".join([
        f"ProofScan scan {scan.id}: {scan.target}, {scan.started_at}",
        compare.format_table(result),
        compare.format_matrix(result),
    ])

    print(report)

    if args.output:
        with open(args.output, "w", encoding="utf-8") as handle:
            handle.write(report + "\n")
        print(f"\nwritten to {args.output}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
