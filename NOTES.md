# Working notes

Where the project is and what comes next. Update this as things change.

## Where it stands

Commits so far:

- `80e0a98` initial commit - scope, http client, crawler, test app
- `2009b91` sqli detector and true/false validator
- `aa104c5` working notes
- `2ae5e9f` timing validator for blind sqli
- `aafa5d5` dvwa as a benchmark target, and the docker fixes
- `6bbb316` authentication, and stopping the scanner wrecking its own scan
- `ebf663d` measure the page's own noise instead of guessing a threshold
- `f95a42f` xss detector and browser validator
- `5464dbc` the full end to end scan numbers for both targets
- `559df38` cvss v3.1 scoring, cwe numbers and owasp categories

60 tests passing, 83s for the suite.

Full scan of the test app, everything switched on, 7 Sep 2026:

```
10 pages, 10 injection points
12 suspicious -> 7 proved, 5 false alarms removed (42%)
195 requests, 59s

confirmed  sqli  /product [id], /login [username], /login [password]
                 /blind-product [id]    <- timing, the true/false test rejected it
           xss   /search [q], /comment [q], /product [id]
rejected   sqli  /safe-product [id], /jitter [id]
           xss   /safe-search [q], /plain [q], /jitter [id]
```

Matches ANSWER_KEY exactly. No false positives, no false negatives, on either
vulnerability class.

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
- [x] form login, session kept, csrf tokens read off the page
- [x] redirects followed by hand, scope checked on every hop
- [x] logged out detection and automatic re login
- [x] dangerous forms and links left alone, so the scan cannot wreck itself
- [x] `--cookie` for apps that keep state there
- [x] dvwa scanned end to end, 3 real findings, 0 false positives
- [x] xss detector (stage 1, reflection only, noisy on purpose)
- [x] xss browser validator (stage 2, chromium, proves the script actually ran)
- [x] xss confirmed on dvwa, reflected and both stored, 0 false positives
- [x] cvss v3.1 base scores, cwe numbers, owasp top 10 2021 categories
- [x] findings come back worst first, because that is the order they get fixed in

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

First crawl of DVWA, 7 Sep 2026, before any authentication support existed:

```
1 pages, 0 injection points in 1 requests
```

One request, nothing found. `/` answers 302 to `/login.php`, redirects were off,
so the crawler got a redirect with no html in it, found no links and stopped.

Full scan of DVWA, everything switched on, 7 Sep 2026. **This is the number for
the report.**

```
48 pages, 20 injection points
12 suspicious -> 6 proved, 6 false alarms removed (50%)
364 requests, 2m 45s

CONFIRMED
  sqli  brute      [username]  true/false, 0.9948 against a floor of 1.0000
  sqli  sqli       [id]        true/false, 0.9687
  sqli  sqli_blind [id]        timing, 10001 ms gap, ranges never overlap
  xss   xss_r      [name]      script ran in chromium
  xss   xss_s      [txtName]   script ran in chromium, stored, POST
  xss   xss_s      [mtxMessage]script ran in chromium, stored, POST
REJECTED
  sqli  fi [page], instructions.php [doc], open_redirect info.php [id]
  xss   fi [page], csp [include], cryptography [message]
```

Every one of the six confirmed is a genuine DVWA vulnerability and every one of
the six rejected is genuinely not one. **No false positives and no false
negatives inside the v1 scope**, with one exception written up below.

Coverage against what DVWA actually has, in scope:

- sql injection: sqli, sqli_blind, brute. All three found.
- xss: xss_r, xss_s found. **xss_d not found**, it is DOM based, see below.

Out of scope by design and correctly left alone: command injection, file
inclusion, csrf, file upload, weak session ids, open redirect. `fi [page]` is a
real file inclusion bug and gets rejected here, which is right, because it is
not sql injection and not xss and this is a v1 scanner for those two.

**Six real findings on an app I did not write, no false positives.** Each is
proved by the validator that suits it: the sql injections that change the page
by the true/false test, the blind one by the clock, the cross site scripting by
a browser that actually ran the script. The timing validator and the browser
validator had, until today, only ever been proved against a lab app I wrote
myself. They work on one I did not.

`brute [password]` is found and correctly not confirmed. DVWA runs the password
through md5 before it reaches the query, so it genuinely is not injectable. That
is a correct negative, not a miss, and it is worth saying out loud in the report
because it looks like a miss until you read the source.

## Seven things DVWA broke, and what each one taught

Getting from 0 to 3 took seven separate fixes. Every one of them was invisible on
the lab app and every one is worth a paragraph in the report.

1. **The crawler dropped submit buttons.** DVWA's sql injection page runs no
   query at all without `Submit=Submit`, so the response never changed and the
   page looked safe. Named fields now all go in the payload, buttons included,
   but buttons are still never injected into.
2. **DVWA keeps its security level in a cookie** and hands out
   `security=impossible` at login, which is the fully patched build. A scanner
   that never sets the cookie is scanning an app with nothing wrong with it and
   cannot tell. Hence `--cookie name=value`.
3. **The scanner changed the target's admin password and locked itself out.**
   Once submit buttons were being sent, DVWA's change password form started
   firing, the validator's own baseline value went into both password boxes at
   once, they matched, and the password became "test" half way through the scan.
   Any form with two or more password boxes is now left alone.
4. **AND payloads get short circuited away.** `user_id = 'test' AND SLEEP(2)`
   never sleeps, because no user is called test, so the database settles the
   answer before it reaches the sleep. Timing payloads now come in AND and OR
   form, and the OR form is what found DVWA's blind injection.
5. **A sleep can fire once per row.** Two seconds against five users is ten, the
   timeout was ten, and the client hung up on a payload that was working
   perfectly. Timing requests now get a much longer timeout, with a time budget
   so one point cannot run away with the whole scan.
6. **`OR '1'='1'` misses anything that wants exactly one row.** A login check
   reads "all five users" as failure, the same as "no users", so the true and
   false responses came back byte identical and a real injection was rejected.
   `LIMIT 1` gives the true side one row and the false side none. This is what
   DVWA's brute force page needed, and it was only being caught at all because
   the timing test happened to rescue it.
7. **The 0.98 similarity threshold was a guess, and wrong.** Logged in versus
   rejected on DVWA's brute force page scores 0.9948, because the difference is
   60 bytes inside a 4.5 kB template. A real difference, thrown away as noise.
   The threshold is now measured per page instead: ask the same question three
   times, see how much the page disagrees with itself, and make the true/false
   pair beat that. Quiet pages set a high bar, noisy ones set a low one, which
   is the right way round. Anything that looks like a hit is then asked a second
   time, because a real difference repeats and a fluctuation does not.

Correction to an earlier note in this file: the security level being
"impossible" was **not** the scanner posting to security.php. It is the cookie
default, and it was read back in a fresh session both times, which made it look
like the scan had done it. Leaving security.php alone is still right, and
setup.php genuinely can rebuild the database mid scan, but that was not the
evidence for it.

## XSS, and what the browser settled

`detectors/xss.py` only asks whether the input comes back. `validators/
xss_browser.py` decides, by sending a payload that sets one variable to a value
only this run knows, loading the page in headless chromium and asking the
browser what that variable holds. Nothing else can set it. There is no inference
left to argue with.

Lab app: `/search`, `/comment` and `/product` confirmed, `/plain`, `/safe-search`
and `/jitter` rejected. All six correct.

DVWA, security low:

```
CONFIRMED  xss_r [name]        reflected
           xss_s [txtName]     stored, POST
           xss_s [mtxMessage]  stored, POST
REJECTED   csp [include]       reflects unescaped, CSP blocks it running
           cryptography [message], fi [page]
```

**`csp [include]` is the best single argument in the project.** The payload comes
back completely unescaped. Anything deciding from the response body calls that a
vulnerability. It is not one, because the page sends a Content-Security-Policy
header and the browser refuses to run the script. Only actually running it can
tell those two apart, and that is the whole thesis in one endpoint.

`/product` on the lab app was **not planted**. ProofScan found it and I had to go
and check before believing it: the error handler puts the sqlite error into the
page with `<pre>{e}</pre>`, and sqlite quotes the offending input back inside
that message, so the payload arrives unescaped and runs. ANSWER_KEY was wrong and
has been corrected. Error messages echoing input is one of the commonest ways
this happens for real.

Known limitation: DOM based xss is not detected. `xss_d` on DVWA is invisible to
the detector because the payload never appears in the server's response at all,
it is handled entirely in javascript. Finding those means watching the DOM rather
than the response, which is phase 2. Say it in the report rather than let someone
find it.

## Scoring

`scoring.py`. CVSS v3.1 base score, CWE number, OWASP Top 10 2021 category. The
arithmetic is the published formula including its own integer rounding rule, and
`test_scoring.py` checks it against vectors whose scores are published rather
than against whatever this code happens to produce. That caught me writing down
a reference vector from memory and getting it wrong: the code said 6.0, I had
written 6.1, and the code was right.

What comes out:

```
                   lab app (no login)   dvwa (behind a login)
sqli   CWE-89      9.8 Critical         8.8 High
xss    CWE-79      6.1 Medium           5.4 Medium
```

**Only proved findings are scored.** Putting a decimal point on something the
scanner could not prove is the exact habit this project argues against, so
REJECTED and UNCONFIRMED findings carry no score at all, and there is a test
that keeps it that way.

**One metric is observed, the rest are conventional, and the report says which
is which.** Privileges Required comes from whether the scan needed credentials
to reach the point, which is a fact this tool actually knows. Everything else is
the vector normally accepted for the class. Each score carries a sentence saying
what was *not* proved: ProofScan shows the database evaluates injected input,
but it never reads the data out, because a scanner that did that to prove a
point would be causing the damage it is reporting.

That PR choice is a simplification and is written down as one. A reflected xss
behind a login can still be reached by somebody with no account at all, by
sending the link to a person who has one.

## Next

1. sqlite evidence store
2. pdf report
3. benchmark against owasp zap on dvwa and one other target. not juice shop,
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
- **Redirects are followed by hand, one hop at a time, with the scope checked on
  every hop.** httpx will follow them internally, but then the scope check only
  ever sees the url we asked for, and one redirect could put us on a host nobody
  gave us permission to touch. This is the whole first principle of the project,
  so it does not get delegated to a library.
- **Timing payloads come in AND and OR form, always both.** Databases stop
  evaluating as soon as the answer is settled, so AND misses when the starting
  value matches no row and OR misses when it matches one. Which applies depends
  on data we cannot see. Sending both is the only way to cover it.
- **A form with two or more password boxes is never submitted.** One box is a
  login and a fair target. Two is a form whose purpose is to change the
  credentials we are scanning with, and it will.
- **The scanner must not change what it is measuring.** Logout, setup, security
  and settings pages are in scope and left alone anyway. A finding that comes
  after the scanner has altered the target is not a finding.
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
