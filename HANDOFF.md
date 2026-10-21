# ProofScan — handoff brief

Paste this into a new chat to bring it up to speed. Written 22 Oct 2026.

Deeper detail lives in `NOTES.md` (~600 lines) in the same folder: every design
decision with its reasoning, the seven things DVWA broke, the full benchmark
write-up. Read this file first, then `NOTES.md` when you need the why.

---

## 1. What this is

**ProofScan** — an automated web vulnerability scanner that proves its own
findings instead of guessing at them.

B.Tech major project, Group 105, School of Electronics Engineering, KIIT.
Students: Abul Kalam Azad (2330060), Tazil Khan (2330200).
Supervisor: Prof. Swetaleena Sahoo.
**Deadline: 15 November 2026.** Effectively solo work.

**The argument.** Normal scanners report "this might be a problem" and a human
has to check every alert by hand. ProofScan runs a second active stage that
tries to prove each candidate is real, and only what it can prove reaches the
report. Three verdicts: CONFIRMED, UNCONFIRMED, REJECTED.

Three proof techniques:
- **SQLi, true/false** — send an always-true and an always-false condition,
  identical apart from the condition. If the responses differ meaningfully, the
  database evaluated the input.
- **SQLi, timing** — for blind injection where the page never changes. Both
  payloads carry a delay, one behind a true condition and one behind a false
  one. Confirmed only if the medians are far apart *and* the slowest false
  sample is quicker than the fastest true one.
- **XSS, real browser** — load the page in headless Chromium and ask the browser
  whether the injected script actually ran. Reflection is not execution.

---

## 2. Current state: ~55% complete, 24 days left

Code is in good shape. **The dissertation has not been started.** That is the
whole risk.

### Built and working

| Component | File | State |
|---|---|---|
| Scope / rules of engagement | `proofscan/config.py` | Done |
| Rate-limited HTTP client | `proofscan/http_client.py` | Done |
| Crawler | `proofscan/crawler.py` | Done |
| Form login, session recovery | `proofscan/auth.py` | Done |
| SQLi detector + 2 validators | `proofscan/detectors/sqli.py`, `validators/sqli_*.py` | Done |
| XSS detector + browser validator | `proofscan/detectors/xss.py`, `validators/xss_browser.py` | Done |
| CVSS v3.1 / CWE / OWASP scoring | `proofscan/scoring.py` | Done |
| SQLite evidence store | `proofscan/store.py` | Done |
| PDF report | `proofscan/report.py` + `templates/` | Done |
| ZAP benchmark harness | `benchmark/` | Done |
| Web interface (demo) | `web/` | Done, 22 Oct |

~2,800 lines of scanner and web UI, ~1,900 lines of tests. **171 tests passing**,
4 skipped when DVWA is down. Suite takes ~80s.

Repo: https://github.com/Abulkalam1524/proofscan (**5 commits unpushed as of
22 Oct — push them**).

### Measured results — these are real, use them

Full ProofScan scan of **DVWA** (an app the student did not write), 7 Sep:
```
48 pages, 20 injection points, 364 requests, 2m 45s
12 suspicious -> 6 proved, 6 false alarms removed (50%)
```

**Benchmark against OWASP ZAP 2.17.0 on DVWA, 8 Sep. The headline result:**
```
                                 alerts  correct  false  missed  precision  recall
ProofScan, verification off          12        6      6       1       0.50    0.86
ProofScan, verification on            6        6      0       1       1.00    0.86
OWASP ZAP                             7        6      1       1       0.86    0.86

ZAP reported 95 further alerts in classes ProofScan does not look for.
```
Verification doubles precision, 0.50 → 1.00, at no cost in recall.

Same benchmark on the self-written lab target:
```
ProofScan, verification off          12        7      5       0       0.58    1.00
ProofScan, verification on            7        7      0       0       1.00    1.00
OWASP ZAP                             5        5      0       2       1.00    0.71
```

**The single best finding in the project:** `/vulnerabilities/csp [include]` on
DVWA. ZAP reports it as reflected XSS, High risk. It is not exploitable — the
page sends a Content-Security-Policy header and the browser refuses to run the
script. ProofScan's stage 1 flags it too, and the browser validator throws it
out. The industry-standard tool reporting a bug that is not there, on a target
neither of us wrote, settled by a real browser.

**Second finding worth a section:** ZAP submitted DVWA's change-password form
(`password_new`, `password_conf`, `Change` all appear in ZAP's own report) and
left the admin password changed. ProofScan hit this same bug and fixed it with
the rule that a form with two or more password boxes is never submitted. ZAP has
no such rule.

### Honest caveats that must stay in the write-up

- ZAP **found** the blind SQL injection. Its time-based rules work.
- All three rows have **identical recall**. Everyone missed `xss_d` (DOM-based).
- ZAP reported **95 alerts in other classes** against ProofScan's zero. The
  framing is a **trade of coverage for precision**, never "ProofScan beats ZAP".
- **Neither scanner logged itself in.** The session was fetched outside and
  handed to both. Fair, but it is not the tools authenticating themselves.
- The lab target was written by the same person as the scanner, so ZAP's misses
  there are weak evidence. DVWA is the result; the lab is corroboration.
- Proposal slide 8 predicted 93% for ProofScan and 54% for ZAP. Both were wrong.
  Show predicted vs measured side by side; do not quietly replace the old table.

---

## 3. NOT built — promised in the proposal deck

| Promise | Where | Status |
|---|---|---|
| **Dissertation document** | The deliverable | **0 pages** |
| Broken access control / IDOR | Slide 5, one of three headline techniques | Not built |
| Screenshot evidence per finding | Slide 3 obj. 5, and slide 5 | Not built |
| Flask dashboard | Slide 7, tools list | **Built 22 Oct**, `web/`, see section 8 |
| 4 targets (DVWA, Juice Shop, WebGoat, bWAPP) | Slide 8 | DVWA + own lab only |
| Final presentation | Viva | Proposal deck only |

WeasyPrint is listed on slide 7 but Chromium's `page.pdf()` was used instead
(WeasyPrint needs GTK on Windows and will not install). Needs one paragraph in
the dissertation, not silence.

Juice Shop is genuinely out of reach: it is an Angular SPA and the crawler does
not run JavaScript. State it as a limitation.

---

## 4. Plan for the remaining 24 days

**The remaining time is for writing, not building.** A project with two
vulnerability classes and an excellent write-up scores better than one with four
classes and a rushed one.

**Do:**
1. **Dissertation, 25–30 h.** Start with the Results chapter — the benchmark
   numbers above are ready to go. `NOTES.md` is a draft in the wrong register,
   not a blank page.
2. **Final presentation, 5 h.**
3. **Screenshots, 3 h.** Chromium is already open during XSS validation.
   Promised twice in the deck, cheapest credibility win available.
4. **Re-run DVWA benchmark 3×, 2 h**, with the change-password page excluded, so
   the Results chapter can say the numbers are stable and the target never moved.

5. **Rehearse the demo twice on a cold machine** (section 8). Find out in your
   own room that Docker takes minutes to start, not in theirs.

**Cut, and say so in writing as future work:**
- Broken access control (10–12 h). **Write the scope reduction deliberately** —
  slide 5 promises three techniques and the demo shows two. Do not leave that
  gap for an examiner to find.
- WebGoat / bWAPP, unless everything above is finished early.

The web interface was originally on the cut list. It came back once it was
clear the instructors are not security specialists and judge by watching: for
that audience the demo is the grading surface, and a terminal is a poor one.

---

## 5. Decisions already made — do not reopen

- Stage 1 is **deliberately noisy**. Filtering is the validator's job.
- `strip_payload` before comparing responses, or any page that echoes input looks
  injectable.
- True and false payloads must differ **only in the condition**.
- **Three verdicts**, not two. Version-based guesses are never CONFIRMED.
- The timing test compares **two payloads**, not payload vs baseline.
- Two rules before a timing finding is confirmed: medians far apart **and**
  ranges must not overlap.
- The timing test is **not gated by the detector** — blind SQLi is invisible to
  stage 1 by definition.
- The similarity threshold is **measured per page**, not a fixed 0.98.
- Timing payloads come in **AND and OR form, always both**.
- **A form with two or more password boxes is never submitted.**
- The scanner must not change what it is measuring (logout, setup, security
  pages avoided).
- **No ML or AI in the detection path.** The point is proof, not probability.
- SQLite, single file. WeasyPrint ruled out. **v1 scope is sqli + xss only.**
- The report renders with **autoescaping on** — it prints working XSS payloads
  and is opened in a browser to make the PDF.
- The benchmark is scoped to **SQLi and XSS only**; ZAP's other alerts are
  counted and shown separately, never dropped.
- The answer key lives outside the `proofscan` package so the scanner cannot
  import the answers.

---

## 6. How to run it

```bash
venv\Scripts\activate

# lab target (terminal 1, leave running)
python labs\vulnerable_app\app.py                 # http://127.0.0.1:5001

# scan it (saves to evidence/proofscan.db)
python main.py scan http://127.0.0.1:5001
python main.py scans                              # list stored scans
python main.py show 1                             # reprint one from the file
python main.py diff 1 2                           # what changed between scans
python main.py report 1                           # PDF to reports/
python main.py web                                # web UI, http://127.0.0.1:8000

pytest -q                                         # 171 tests, ~80s
```

DVWA (Docker Desktop must be started **by hand** first):
```bash
docker compose -f labs/dvwa/docker-compose.yml up -d
python labs\dvwa\reset_dvwa.py                    # BEFORE EVERY SCAN
set PROOFSCAN_PASSWORD=password
python main.py scan http://127.0.0.1:8080 --login-url http://127.0.0.1:8080/login.php --username admin --cookie security=low
```

Benchmark:
```bash
python -m benchmark.run_zap --target http://dvwa/ --network dvwa_default \
    --login-dvwa --login-url http://127.0.0.1:8080 --out reports/zap-dvwa.json
python -m benchmark --scan 3 --zap reports/zap-dvwa.json --key dvwa
```

---

## 7. Environment traps — read before debugging

- **Python 3.12.1**, venv in `venv/`. Chromium for Playwright installed.
- Both targets are **servers**. "Cannot connect" usually means nothing is broken,
  the target just is not running.
- **Docker Desktop does not start with Windows.** Start it by hand. If it hangs
  with the `docker-desktop` WSL distro Stopped, rename
  `%LOCALAPPDATA%\Docker\run` and restart it — stale sockets.
- **`reset_dvwa.py` before every DVWA scan.** Scanning changes DVWA's state and
  two runs that did not start from the same place are not comparable.
- **`--cookie security=low` is mandatory on DVWA.** Without it DVWA serves the
  fully patched build and any scanner reports a clean site.
- **Windows Defender quarantines the native ZAP download** (it ships attack
  payloads). Use the Docker image `ghcr.io/zaproxy/zaproxy:stable` instead.
- ZAP plan YAML: regex excludes **must be single-quoted**. A double-quoted
  `".*setup\.php.*"` makes ZAP's parser die four seconds in while the container
  still looks healthy and exits zero.
- **WebGoat 2023.8 will not run** on the JDKs on this machine (XNIO provider
  fails on Java 19/21, wants JDK 17). Use Docker if it is needed at all.
- Commits must **not** carry AI attribution trailers.

---

## 8. The demo

The instructors are not security specialists and understand by watching, so the
demo matters as much as the document. `python main.py web`, then open
http://127.0.0.1:8000.

**Replay first, always.** "Replay a saved scan" reads the evidence file and shows
a full scan instantly with nothing else running: no Docker, no target, no wait.
A live scan takes ~45s on the lab app and ~3 min on DVWA, mostly the timing test
waiting on purpose, and depends on Docker, the target and Chromium all working on
the day. Use live scanning as a bonus if the room cooperates, never as the plan.

Stored scans to demo from (in `evidence/proofscan.db`):
- **#3 — DVWA**, logged in: 12 suspicious, 6 proved, 6 thrown out. Contains the
  CSP finding.
- **#4 — lab app**, scanned through the web UI on 22 Oct: 12 suspicious, 7
  proved, 5 thrown out, 42%. Contains `/plain`.

The story, which needs no security knowledge to follow:
1. "Here is a website with a search box." Show the lab app.
2. "A normal scanner says there might be a problem in 12 places." The funnel.
3. Open the thrown-out `/plain` card. "Our text came back on the page, word for
   word. It looks broken. It isn't — the page sends it as plain text, so the
   browser shows it as words instead of running it."
4. "ProofScan opened a real browser and checked whether the code ran. It didn't,
   so it threw this one away." Point at the five attempts, each "nothing ran".
5. Open a PROVED card. "Here the code did run, and here is the proof."
6. "Download the PDF report." The document it writes.
7. Close on DVWA scan #3, the CSP card: **ZAP, the standard professional tool,
   reports this as a High risk vulnerability. It is not one. ProofScan proves
   it.**

Use the XSS examples, not SQL injection. "The browser refused to run it" is
intuitive. "The database evaluated the injected condition" is not.

Safety built in, worth saying out loud in the viva: the web UI refuses any
target that is not on this machine (IT Act 2000), unless started with
`--allow-any`, and it binds to 127.0.0.1 so nobody else on the network can use
it to start scans. It displays working XSS payloads without ever running them:
every value goes in as text, never parsed as html, and a test fails if that
ever changes.

