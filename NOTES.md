# Working notes

Where the project is and what comes next. Update this as things change.

## Where it stands

Commits so far:

- `80e0a98` initial commit - scope, http client, crawler, test app
- `2009b91` sqli detector and true/false validator
- `aa104c5` working notes
- (uncommitted) timing validator, blind endpoint in the test app

17 tests passing, 44s for the suite. Latest scan of the test app:

```
10 pages, 10 injection points
detector flagged 6
  confirmed  /product [id], /login [username], /login [password]
             /blind-product [id]   <- timing test, the true/false test rejected it
  rejected   /safe-product [id], /jitter [id]
6 suspicious -> 4 proved, 2 false alarms removed (33%)
123 requests, 43s
```

That matches ANSWER_KEY exactly. No false positives, no false negatives on sqli.

Worth keeping for the report: with `--safe-mode` the timing tests are skipped and
`/blind-product` comes out REJECTED, a real bug written off as a false alarm.
That is the whole argument for having two validators instead of one, and it is
one command apart.

## Done

- [x] scope / rules of engagement, allow list checked before every request
- [x] http client, rate limited, records elapsed_ms on every response
- [x] crawler, finds pages, query params and form fields
- [x] test app with deliberate bugs and planted traps
- [x] sqli detector (stage 1, noisy on purpose)
- [x] sqli true/false validator (stage 2)
- [x] sqli timing validator (stage 2, for the blind case)
- [x] `/blind-product` in the test app, injectable but silent
- [x] `--safe-mode` wired up, skips the timing tests
- [x] accuracy tests against ANSWER_KEY

## DVWA, and the number the auth work has to beat

DVWA runs from `labs/dvwa/docker-compose.yml`, two containers, pinned versions,
bound to 127.0.0.1 only. `labs/dvwa/reset_dvwa.py` creates the database and sets
the security level, and has to be run before every benchmark, because scanning
changes DVWA's state and a run that does not start from the same place is not
comparable to the last one.

```
docker compose -f labs/dvwa/docker-compose.yml up -d
python labs/dvwa/reset_dvwa.py          # admin / password, security low
python main.py crawl http://127.0.0.1:8080
```

First crawl of DVWA, 7 Sep 2026, before any authentication support exists:

```
Pages found (1):
  http://127.0.0.1:8080
Injection points (0):
1 pages, 0 injection points in 1 requests
```

One request, nothing found, scanner blind. `/` answers 302 to `/login.php`,
`follow_redirects` is off, so the crawler gets a redirect with no html in it,
finds no links and stops. **That zero is the before number.** Whatever the auth
support turns it into is the after number, and both belong in the report.

## Next

1. **authentication and sessions** - the thing standing between ProofScan and
   any real target. Needs a login step, a per request redirect override
   (`follow_redirects=False` is right for detection and wrong for logging in),
   and a logged out detector so the crawler notices when its session dies
   halfway through instead of quietly scanning the login page 200 times.
2. **xss detector + browser validator** - `detectors/xss.py`,
   `validators/xss_browser.py`. Payload sets a unique window variable, load the
   page in headless chromium, check `window.__proof`. Must confirm `/search` and
   `/comment`, must reject `/plain`, which reflects the payload but returns
   text/plain so nothing runs. Chromium is already installed.
3. cvss v3.1 scoring and cwe mapping
4. sqlite evidence store
5. pdf report
6. benchmark against owasp zap on dvwa and one other target. not juice shop,
   it is an angular spa and the crawler does not run javascript. that is a
   stated limitation in the report, not a bug to fix in the time left.

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
- **The timing test compares two payloads, not payload against baseline.** Both
  carry the sleep, one behind a true condition and one behind a false one, so
  they are the same length and take the same path. A plain baseline is shorter
  and parses differently, which leaves something other than the database to
  explain a gap. Same reasoning as the true/false rule above.
- **Two rules before a timing finding is confirmed**, and the second one is the
  one that matters: the medians must be apart by most of the delay asked for,
  *and* the slowest false sample must still be quicker than the fastest true
  one. Random slowness lands in both sets and makes the ranges overlap, so it
  fails the second rule. A real sleep never overlaps.
- **2 second delay, because /jitter stalls for 1.** Anything at or under a
  second cannot be told apart from the trap.
- **One cheap request before committing to twenty.** Most payloads are the wrong
  dialect and come back at normal speed, and 20 samples at every point of every
  dialect would take all day. Only a payload that already looks slow earns the
  full sample set.
- **The timing test is not gated by the detector.** Every other check runs only
  on what stage 1 flagged. Blind sqli is by definition the case where the page
  never changes, so stage 1 has nothing to notice, and gating it there would
  mean never finding one. It costs about 5 extra requests per injection point.
- **`/blind-product` needed a sleep function, sqlite has none.** The lab
  registers one. Every real database already ships something like it, mysql
  `SLEEP()`, postgres `pg_sleep()`, sql server `WAITFOR DELAY`. Without it there
  is no honest way to test that the validator confirms a real delay.
- **The statistics are tested on made up samples,** in `test_sqli_timing.py`,
  not against the live app. Live, `/jitter` gets rejected at the cheap first
  request because 1 second is under the threshold, so the separation rule never
  runs there. Feeding it numbers is the only way to actually test the rule that
  does the work.
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
python labs\vulnerable_app\app.py                      # terminal 1, leave running
python main.py scan http://127.0.0.1:5001              # terminal 2, about 45s
python main.py scan http://127.0.0.1:5001 --safe-mode  # no timing tests, about 13s
pytest -q
```

The scan takes about 45 seconds now. Most of that is the timing test waiting on
purpose, 10 samples of a 2 second sleep. That is the cost of catching the blind
case and there is no way around it.

The test app is a server. It only runs while the terminal is open. If a scan or
a test says it cannot connect, the app is just not running, start it again.

## Environment

Python 3.12.1, venv in `venv/`. Chromium for playwright is installed.
Java 19 is installed. No node, no npm, no php, no xampp.

**Docker works now, as of 7 Sep 2026.** Server 29.7.2, WSL2 backend, Ubuntu and
docker-desktop distros both present. Getting there took two separate fixes and
only the first one was obvious:

1. WSL was not installed at all. This is Windows 11 Home, which supports the
   WSL2 backend only, so Docker Desktop had nothing to run on. `wsl --install`
   plus a reboot fixed that.
2. Docker Desktop still would not start after the reboot. It was dying on a
   stale unix socket left behind by an earlier crash, in
   `%LOCALAPPDATA%\Docker\run\`. The real error is only in the log, the dialog
   just says "an unexpected error occurred":

       initializing Ingest server: listening on .../run/sailor-ingest.sock:
       rename ... sailor-ingest.sock.stale: The file cannot be accessed by the system

   The orphaned sockets cannot be deleted by anything, not `del`, not .NET,
   because the object behind them is gone. **Rename the whole `run` folder
   instead.** Docker makes a fresh one on the next start. If Docker ever refuses
   to start again, look here first.

**WebGoat 2023.8 will not run on the JDKs on this machine.** The jar is
downloaded and sitting in `labs/webgoat/`, gitignored. It dies at startup with
`XNIO001001: No XNIO provider found`, which is Undertow failing to bring up its
network layer. Ruled out, in this order, so nobody wastes the afternoon again:

- not the JDK version on its own, it fails the same way on Java 19 and Java 21
- not a bad download, the file size matches the release exactly
- not a packaging fault, `xnio-nio-3.8.8.Final.jar` is in the fat jar and does
  carry its `META-INF/services/org.xnio.XnioProvider` registration
- not the spaces in the project path, it fails from a path with none
- not spring boot's nested jar loader, it fails with a flat classpath too

The jar manifest says `Build-Jdk-Spec: 17` and xnio 3.8.8 predates Java 18, so
the provider itself will not start on a newer jvm. It wants a real JDK 17. Not
worth a third download when docker will hand it over properly with the right jvm
inside the container.
