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
]

# similarity above this counts as "the same response"
SAME = 0.98


def validate(client, point, reason):
    base = point.value or "1"
    attempts = []

    for true_suffix, false_suffix in PAYLOAD_PAIRS:
        true_payload = base + true_suffix
        false_payload = base + false_suffix

        try:
            t = send(client, point, true_payload)
            f = send(client, point, false_payload)
        except Exception as e:
            return Finding("sqli", point, Verdict.UNCONFIRMED,
                           f"could not complete the test: {e}",
                           {"detector_reason": reason})

        a = strip_payload(t.body, true_payload)
        b = strip_payload(f.body, false_payload)
        score = similarity(a, b)

        attempts.append({
            "true_payload": true_payload,
            "false_payload": false_payload,
            "true_status": t.status,
            "false_status": f.status,
            "true_length": t.length,
            "false_length": f.length,
            "similarity": round(score, 4),
        })

        if score < SAME:
            return Finding(
                "sqli", point, Verdict.CONFIRMED,
                f"true and false conditions gave different responses "
                f"(similarity {score:.2f})",
                {
                    "detector_reason": reason,
                    "proof": attempts[-1],
                    "true_body": t.body[:600],
                    "false_body": f.body[:600],
                },
            )

    return Finding("sqli", point, Verdict.REJECTED,
                   "responses identical for true and false conditions",
                   {"detector_reason": reason, "attempts": attempts})
