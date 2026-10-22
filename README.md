# ProofScan

Automated website security testing with self verification and report generation.

B.Tech major project, Group 105, School of Electronics Engineering, KIIT.

**Live demo: [proofscan.pages.dev](https://proofscan.pages.dev)** (replays real saved scans, cannot scan anything)

![ProofScan replaying a scan of DVWA: 12 suspicious, 6 proved, 6 thrown out](docs/images/demo.gif)

## The problem

Vulnerability scanners report a lot of things that are not real. Someone has to
check every alert by hand, which is the slow part of an assessment. In an
assessment I did on a practice lab, 39% of the scanner's findings had to be
rejected as unconfirmed.

ProofScan does that checking automatically. Each candidate finding gets an
active test that tries to prove it is real. Only what it can prove goes in the
report, along with the request and response that proves it.

## How the verification works

**SQL injection, true/false test.** Send a condition that is always true and one
that is always false. If the two responses come back different, the database
actually evaluated the input.

**SQL injection, timing test.** Send two inputs that both carry a delay, one
behind a true condition and one behind a false one, ten times each. One slow
reply proves nothing. It is confirmed only if the true side is slower every
single time.

**XSS.** Load the page in a headless browser and check whether the injected
script actually executed. Reflection on its own is not enough.

Every finding ends up as CONFIRMED, UNCONFIRMED (could not prove it safely), or
REJECTED (proved it is not there).

## What it looks like

Every finding comes with what the browser actually showed.

**Proved SQL injection.** The always-true input logs in, the always-false one
does not, so the database evaluated what we typed.

![A proved SQL injection on DVWA's brute force page, true and false pages side by side](docs/images/proved-sqli.png)

**Proved XSS.** After the proof, ProofScan sends one more script that draws the
red box. The picture is kept only if the browser hands back that script's own
random token.

![A proved XSS on DVWA, with the red box drawn by the injected script](docs/images/proved-xss.png)

**Thrown out.** OWASP ZAP reports this page as High risk XSS. The input does
come back unescaped, but the page's Content-Security-Policy stopped all five
payloads from running, so ProofScan threw it out.

![DVWA's CSP page, thrown out because nothing ran](docs/images/thrown-out-csp.png)

## Results

Benchmarked against OWASP ZAP 2.17.0 on DVWA (security level low), scored on SQL
injection and XSS against a hand-written answer key:

| | Alerts | Correct | False alarms | Missed | Precision | Recall |
|---|---|---|---|---|---|---|
| ProofScan, verification off | 12 | 6 | 6 | 1 | 0.50 | 0.86 |
| ProofScan, verification on | 6 | 6 | 0 | 1 | **1.00** | 0.86 |
| OWASP ZAP | 7 | 6 | 1 | 1 | 0.86 | 0.86 |

Verification doubles precision with no loss of recall. The numbers were the same
across four ProofScan scans and two ZAP scans, six weeks apart. ZAP also reported
89 alerts in classes ProofScan does not look for, so this is a trade of coverage
for certainty, not a claim that ProofScan beats ZAP. Everyone missed DOM-based
XSS.

## Verify mode: checking ZAP's findings

ProofScan can also take another scanner's report and prove or reject each
finding. ZAP does the finding, including JavaScript-heavy pages and far more
kinds of problem. ProofScan does the proving. Each ZAP alert is rebuilt into a
full request by reading the form on that page, then sent through the same
validators a scan uses.

```
python main.py verify reports/zap-dvwa.json --rewrite http://dvwa=http://127.0.0.1:8080     --login-url http://127.0.0.1:8080/login.php --username admin --cookie security=low
```

On DVWA, ZAP's 7 SQL injection and XSS alerts:

| | Alerts | Correct | False alarms | Missed | Precision | Recall |
|---|---|---|---|---|---|---|
| ZAP alerts, as reported | 7 | 6 | 1 | 1 | 0.86 | 0.86 |
| ZAP alerts, verified by ProofScan | 6 | 6 | 0 | 1 | **1.00** | 0.86 |

The one removed is the CSP page above. It took 78 requests, against 368 for a
full ProofScan scan, because ZAP had already done the searching.

## Architecture overview

A scan runs top to bottom. Stage 1 is quick and flags anything suspicious.
Stage 2 tries to prove each one, and only what it proves is scored. Everything,
including what was thrown out and why, is saved, and the report, the web
interface and the ZAP benchmark all read from that saved copy. Every request to
the target goes through the safety rules on the right.

```mermaid
flowchart TB
    subgraph START["1. Start a scan"]
        direction LR
        CLI["💻 Command line<br/>python main.py scan"]
        WEB["🖥️ Web interface<br/>python main.py web"]
    end

    subgraph DISCOVER["2. Discovery"]
        AUTH["🔑 Login and session recovery<br/>auth.py"]
        CRAWL["🕸️ Crawler<br/>crawler.py"]
        POINTS["📋 Injection points<br/>form fields and URL parameters"]
    end

    subgraph STAGE1["3. Stage 1: Detection (fast, noisy on purpose)"]
        direction LR
        DSQL["SQL injection detector<br/>detectors/sqli.py"]
        DXSS["XSS detector<br/>detectors/xss.py"]
    end

    subgraph STAGE2["4. Stage 2: Verification (the proof)"]
        direction LR
        VBOOL["⚖️ True/false test<br/>sqli_boolean.py"]
        VTIME["⏱️ Timing test<br/>sqli_timing.py"]
        VBROW["🌐 Real browser test<br/>headless Chromium<br/>xss_browser.py"]
    end

    subgraph VERDICTS["5. Verdict"]
        direction LR
        CONF["✅ CONFIRMED<br/>proved real"]
        UNC["❔ UNCONFIRMED<br/>could not prove either way"]
        REJ["❌ REJECTED<br/>false alarm, removed"]
    end

    subgraph SAFETY["Safety rules, on every request"]
        SCOPE["🛡️ Scope allow-list · rate limit<br/>pages to avoid · no password forms<br/>config.py, http_client.py"]
    end

    TARGET{{"🎯 Target website<br/>DVWA or the lab app<br/>local only"}}

    subgraph STORE["6. Storage"]
        SCORE["📊 CVSS v3.1 · CWE · OWASP<br/>scoring.py"]
        DB[("🗄️ SQLite evidence store<br/>scans · findings<br/>proofs · screenshots")]
    end

    subgraph OUTPUT["7. Results"]
        direction LR
        PDF["📄 PDF report<br/>report.py"]
        UI["🖥️ Web UI replay<br/>web/app.py"]
        BENCH["📈 Benchmark vs OWASP ZAP<br/>benchmark/"]
    end

    ZAP["🔍 OWASP ZAP<br/>Docker"]

    CLI -->|"1. Start scan"| AUTH
    WEB -->|"1. Start scan"| AUTH
    AUTH -->|"2. Log in"| CRAWL
    CRAWL -->|"3. Find forms and links"| POINTS
    POINTS -->|"4. Quick checks"| DSQL
    POINTS -->|"4. Quick checks"| DXSS
    DSQL -->|"5. Suspicious"| VBOOL
    POINTS -.->|"5. Every point, for blind SQLi"| VTIME
    DXSS -->|"5. Suspicious"| VBROW
    VBOOL -->|"6. Result"| VERDICTS
    VTIME -->|"6. Result"| VERDICTS
    VBROW -->|"6. Result"| VERDICTS
    CONF -->|"7. Score"| SCORE
    SCORE -->|"8. Save with proof"| DB
    UNC -->|"8. Save"| DB
    REJ -->|"8. Save, with what was tried"| DB
    DB -->|"9. Read back"| PDF
    DB -->|"9. Read back"| UI
    DB -->|"9. Read back"| BENCH
    ZAP -->|"Same target, same session"| BENCH

    DISCOVER -.->|"requests"| SCOPE
    STAGE1 -.->|"requests"| SCOPE
    STAGE2 -.->|"requests"| SCOPE
    SCOPE <-.->|"in scope only, rate limited"| TARGET

    classDef start fill:#2563eb,stroke:#1e40af,color:#fff
    classDef discover fill:#0891b2,stroke:#0e7490,color:#fff
    classDef stage1 fill:#f59e0b,stroke:#b45309,color:#111
    classDef stage2 fill:#10b981,stroke:#047857,color:#fff
    classDef good fill:#16a34a,stroke:#14532d,color:#fff
    classDef unsure fill:#6b7280,stroke:#374151,color:#fff
    classDef bad fill:#dc2626,stroke:#7f1d1d,color:#fff
    classDef safety fill:#374151,stroke:#f59e0b,color:#fff,stroke-width:2px
    classDef target fill:#111827,stroke:#ef4444,color:#fff,stroke-width:2px
    classDef store fill:#7c3aed,stroke:#5b21b6,color:#fff
    classDef output fill:#be123c,stroke:#881337,color:#fff
    classDef zap fill:#4b5563,stroke:#9ca3af,color:#fff

    class CLI,WEB start
    class AUTH,CRAWL,POINTS discover
    class DSQL,DXSS stage1
    class VBOOL,VTIME,VBROW stage2
    class CONF good
    class UNC unsure
    class REJ bad
    class SCOPE safety
    class TARGET target
    class SCORE,DB store
    class PDF,UI,BENCH output
    class ZAP zap
```

## Status

Phase 1, in progress.

- [x] scope / rules of engagement
- [x] http client with rate limit and timing
- [x] crawler
- [x] local test target
- [x] authentication, sessions and logged out recovery
- [x] detectors, sql injection and cross site scripting
- [x] validators, true/false, timing and headless browser
- [x] cvss v3.1 scoring, cwe and owasp mapping
- [x] evidence store
- [x] pdf report
- [x] benchmark against zap
- [x] web interface
- [x] screenshot evidence
- [x] repeat runs, results stable
- [x] verify mode for ZAP findings

## Setup

```
python -m venv venv
venv\Scripts\activate
pip install -r requirements.txt
playwright install chromium
```

## Running it

Start the test target in one terminal:

```
python labs/vulnerable_app/app.py
```

Crawl it from another:

```
python main.py crawl http://127.0.0.1:5001
```

Every scan is written to `evidence/proofscan.db`, and can be read back
without running the target again:

```
python main.py scans          # every scan in the file
python main.py show 1         # one scan, findings and proofs
python main.py diff 1 2       # what was fixed, what is new, what is still there
python main.py report 1       # one scan, as a pdf
```

Or open the web interface, which shows the same results on one page and can
replay any stored scan instantly, with nothing else running:

```
python main.py web            # http://127.0.0.1:8000
```

The pdf is written from the stored scan and never re-runs anything. It carries
the proof behind every confirmed finding, the CVSS score with a note saying
which metric was observed and which came from the class, and the candidates that
were thrown out along with what was tried against each.

Tests:

```
pytest -v
```

## The test target

`labs/vulnerable_app/` is a small flask app with deliberate bugs. It also has
safe endpoints that look vulnerable, which is the point:

- `/plain` reflects the input exactly but returns plain text, so nothing runs
- `/jitter` is randomly slow
- `/safe-product` and `/safe-search` are the fixed versions

It also has one that works the other way round. `/blind-product` is genuinely
injectable but returns the same page every time, no error, no missing row,
nothing. The true/false test cannot prove anything there and rejects it. Only
the timing test finds it. Running a scan with `--safe-mode`, which skips the
timing tests, turns it back into a missed bug.

If the scanner flags any of those, the verification stage is broken. `ANSWER_KEY`
in `app.py` lists what is actually there.

Binds to 127.0.0.1 only.

## Scope

The scanner refuses any host not on the allow list, rate limits every request
and only sends non destructive input. All testing here is against local apps
built to be tested: the target above, plus DVWA.

Scanning a system without permission is an offence under the IT Act, 2000.

## Standards

OWASP Top 10 (2021), OWASP WSTG v4.2, CVSS v3.1, CWE, NIST SP 800-115.

## License

MIT, see [LICENSE](LICENSE).
