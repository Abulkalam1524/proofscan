# Working notes

Where the project is and what comes next. Update this as things change.

## Where it stands

Commits so far:

- `80e0a98` initial commit - scope, http client, crawler, test app
- `2009b91` sqli detector and true/false validator

8 tests passing. Latest scan of the test app:

```
9 pages, 9 injection points
detector flagged 5
  confirmed  /product [id], /login [username], /login [password]
  rejected   /safe-product [id], /jitter [id]
5 suspicious -> 3 proved, 2 false alarms removed (40%)
```

That matches ANSWER_KEY exactly. No false positives, no false negatives on sqli.

## Done

- [x] scope / rules of engagement, allow list checked before every request
- [x] http client, rate limited, records elapsed_ms on every response
- [x] crawler, finds pages, query params and form fields
- [x] test app with deliberate bugs and planted traps
- [x] sqli detector (stage 1, noisy on purpose)
- [x] sqli true/false validator (stage 2)
- [x] accuracy tests against ANSWER_KEY

## Next

1. **timing validator** - `validators/sqli_timing.py`. Send `1' AND 1=1--` style
   payloads with a sleep, take 10 baseline samples and 10 payload samples,
   compare medians and spread. Must NOT flag `/jitter`, which is randomly slow
   about 1 request in 6. `http_client` already records `elapsed_ms`.
2. **xss detector + browser validator** - `detectors/xss.py`,
   `validators/xss_browser.py`. Payload sets a unique window variable, load the
   page in headless chromium, check `window.__proof`. Must confirm `/search` and
   `/comment`, must reject `/plain`, which reflects the payload but returns
   text/plain so nothing runs. Chromium is already installed.
3. cvss v3.1 scoring and cwe mapping
4. sqlite evidence store
5. pdf report
6. benchmark against owasp zap on dvwa, juice shop, webgoat

## Decisions made, do not redo these

- **Stage 1 is deliberately noisy.** The detector should over-report. Filtering
  is the validator's job. Missing a real bug is worse than an extra candidate.
- **strip_payload before comparing responses.** Without it, any page that
  echoes input looks injectable, because the two responses differ only because
  the payloads differ. This is what stops `/search` being confirmed.
- **True and false payloads must differ only in the condition.** Same length,
  same shape, otherwise the comparison means nothing.
- **Three verdicts, not two.** CONFIRMED, UNCONFIRMED, REJECTED. Version-based
  guesses are never CONFIRMED.
- **No ML or AI in the detection path.** The point is proof, not probability.
  If AI is added later it only rewrites report text, never decides a verdict.
- **SQLite, not a server database.** Single file, portable, nothing to secure.
- **WeasyPrint is not installed.** It needs GTK on windows and breaks. Use
  playwright's `page.pdf()` for the report instead, chromium is already there.
- **v1 scope is fixed:** sqli (boolean + timing) and xss. IDOR, command
  injection and open redirect are phase 2. Do not expand.

## Running it

```
venv\Scripts\activate
python labs\vulnerable_app\app.py          # terminal 1, leave running
python main.py scan http://127.0.0.1:5001  # terminal 2
pytest -q
```

The test app is a server. It only runs while the terminal is open. If a scan or
a test says it cannot connect, the app is just not running, start it again.

## Environment

Python 3.12.1, venv in `venv/`. Docker 29.7.2 installed but Docker Desktop has
to be started manually before `docker` commands work. Chromium for playwright is
installed.
