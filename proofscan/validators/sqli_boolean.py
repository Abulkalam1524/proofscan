"""Stage 2 true/false test for SQL injection.

Send an always true and an always false condition that differ in nothing
else. If the two pages differ by more than the page differs from itself,
the database evaluated the input. The payload is stripped out first, so a
page that only echoes input is not confirmed.
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
    # For checks that want exactly one row, like a login. OR '1'='1' returns every
    # user and looks like a failure; LIMIT 1 does not. DVWA's brute force needed it.
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
    """How different is the page from itself? Ask the same thing a few times, take the worst."""
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

        # Looks like a hit. Ask again: a real difference repeats, a fluctuation does not.
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
