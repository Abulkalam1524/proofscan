# Builds the static showcase into showcase/dist: a landing page and a replay-only
# copy of the web UI, reading saved files instead of a server. Nothing in it can scan.
#   python showcase/build.py
#   npx wrangler pages deploy showcase/dist --project-name proofscan --branch main
# live at https://proofscan.pages.dev

import json
import shutil
import sys
from pathlib import Path

HERE = Path(__file__).parent
ROOT = HERE.parent
sys.path.insert(0, str(ROOT))

from proofscan.report import write_pdf  # noqa: E402
from proofscan.store import DEFAULT_PATH, EvidenceStore  # noqa: E402
from web.app import create_app, scan_json  # noqa: E402

DIST = HERE / "dist"
SCANS = [10, 12, 11]  # DVWA, ZAP's DVWA findings verified, the lab app. first one opens by default
NOTES = {12: "ZAP's findings, verified by ProofScan"}


def main():
    if DIST.exists():
        shutil.rmtree(DIST)
    for sub in ("data", "shots", "reports"):
        (DIST / sub).mkdir(parents=True)

    with EvidenceStore(ROOT / DEFAULT_PATH) as store:
        listed = {s.id: s for s in store.scans()}
        rows = []
        for scan_id in SCANS:
            s = listed[scan_id]
            rows.append({"id": s.id, "target": s.target, "started_at": s.started_at,
                         "duration": round(s.duration_seconds),
                         "confirmed": s.confirmed_count, "rejected": s.rejected_count,
                         "safe_mode": s.safe_mode, "authenticated": s.authenticated,
                         "note": NOTES.get(scan_id, "")})

            stored = store.load(scan_id)
            data = scan_json(stored)
            (DIST / "data" / f"scan-{scan_id}.json").write_text(json.dumps(data), encoding="utf8")
            for group in ("confirmed", "rejected", "unconfirmed"):
                for finding in data[group]:
                    for shot in finding["screenshots"]:
                        (DIST / "shots" / f"{shot['id']}.png").write_bytes(store.screenshot(shot["id"]))
            write_pdf(stored, path=DIST / "reports" / f"scan-{scan_id}.pdf")

        (DIST / "data" / "scans.json").write_text(json.dumps(rows), encoding="utf8")

    page = create_app().jinja_env.get_template("index.html").render(showcase=True)
    (DIST / "replay.html").write_text(page, encoding="utf8")

    shutil.copy(HERE / "index.html", DIST / "index.html")
    shutil.copy(ROOT / "docs" / "images" / "demo.gif", DIST / "demo.gif")
    shutil.copy(ROOT / "docs" / "images" / "thrown-out-csp.png", DIST / "thrown-out-csp.png")

    files = [f for f in DIST.rglob("*") if f.is_file()]
    print(f"{len(files)} files, {sum(f.stat().st_size for f in files) / 1e6:.1f} MB in {DIST}")


if __name__ == "__main__":
    main()
