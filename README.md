# ProofScan

Automated website security testing with self verification and report generation.

B.Tech major project, Group 105, School of Electronics Engineering, KIIT.

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

**SQL injection, timing test.** Compare the median of n normal responses against
n delayed ones. One slow reply proves nothing, a consistent gap does.

**XSS.** Load the page in a headless browser and check whether the injected
script actually executed. Reflection on its own is not enough.

Every finding ends up as CONFIRMED, UNCONFIRMED (could not prove it safely), or
REJECTED (proved it is not there).

## Status

Phase 1, in progress.

- [x] scope / rules of engagement
- [x] http client with rate limit and timing
- [x] crawler
- [x] local test target
- [ ] detectors
- [ ] validators
- [ ] cvss scoring
- [ ] evidence store
- [ ] pdf report
- [ ] benchmark against zap

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

If the scanner flags any of those, the verification stage is broken. `ANSWER_KEY`
in `app.py` lists what is actually there.

Binds to 127.0.0.1 only.

## Scope

The scanner refuses any host not on the allow list, rate limits every request
and only sends non destructive input. All testing here is against local apps
built to be tested: the target above, plus DVWA, Juice Shop and WebGoat.

Scanning a system without permission is an offence under the IT Act, 2000.

## Standards

OWASP Top 10 (2021), OWASP WSTG v4.2, CVSS v3.1, CWE, NIST SP 800-115.
