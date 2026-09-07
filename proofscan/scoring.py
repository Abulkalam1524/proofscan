"""CVSS v3.1 base scores, CWE numbers and OWASP Top 10 categories.

A finding that says "sql injection on /product" is not a report. Somebody has to
decide what to fix first, and that means a number they recognise and a category
they can look up. This turns a proved finding into both.

Only proved findings get scored. Putting a decimal point on something the
scanner could not prove is exactly the habit this project exists to argue
against.

The arithmetic is the published CVSS v3.1 formula, including its own peculiar
rounding rule, which is why roundup looks the way it does instead of calling
Python's round(). The specification is deliberate about that: ordinary rounding
gives the wrong answer at the boundaries because of binary floating point, so
the spec does the rounding in integers.
"""
import math
from dataclasses import dataclass, field

# Metric weights, straight from the CVSS v3.1 specification.
ATTACK_VECTOR = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}
ATTACK_COMPLEXITY = {"L": 0.77, "H": 0.44}
USER_INTERACTION = {"N": 0.85, "R": 0.62}
IMPACT = {"H": 0.56, "L": 0.22, "N": 0.0}

# privileges required is worth more when the scope changes, because breaking out
# of the scope you were given counts for more than acting inside it
PRIVILEGES_REQUIRED = {
    "U": {"N": 0.85, "L": 0.62, "H": 0.27},
    "C": {"N": 0.85, "L": 0.68, "H": 0.50},
}

SEVERITY_BANDS = [
    (0.0, "None"),
    (0.1, "Low"),
    (4.0, "Medium"),
    (7.0, "High"),
    (9.0, "Critical"),
]


def roundup(value):
    """The rounding rule from the CVSS v3.1 spec, done in integers.

    Rounding a float gets the boundary cases wrong, because a number like 4.02
    is not exactly 4.02 once it is binary. The spec works in hundred thousandths
    to sidestep that.
    """
    scaled = int(round(value * 100000))
    if scaled % 10000 == 0:
        return scaled / 100000.0
    return (math.floor(scaled / 10000) + 1) / 10.0


def severity_of(score):
    label = "None"
    for floor, name in SEVERITY_BANDS:
        if score >= floor:
            label = name
    return label


def base_score(av, ac, pr, ui, s, c, i, a):
    """CVSS v3.1 base score from the eight base metrics."""
    iss = 1 - ((1 - IMPACT[c]) * (1 - IMPACT[i]) * (1 - IMPACT[a]))

    if s == "U":
        impact = 6.42 * iss
    else:
        impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15

    if impact <= 0:
        return 0.0

    exploitability = (8.22 * ATTACK_VECTOR[av] * ATTACK_COMPLEXITY[ac]
                      * PRIVILEGES_REQUIRED[s][pr] * USER_INTERACTION[ui])

    if s == "U":
        return roundup(min(impact + exploitability, 10))
    return roundup(min(1.08 * (impact + exploitability), 10))


def vector_string(av, ac, pr, ui, s, c, i, a):
    return f"CVSS:3.1/AV:{av}/AC:{ac}/PR:{pr}/UI:{ui}/S:{s}/C:{c}/I:{i}/A:{a}"


@dataclass
class Score:
    cvss_vector: str
    cvss_score: float
    severity: str
    cwe: str
    cwe_name: str
    owasp: str
    observed: dict = field(default_factory=dict)   # metrics taken from the scan
    conventional: str = ""                          # what came from the class

    def __str__(self):
        return f"{self.cvss_score} {self.severity} ({self.cwe}) {self.cvss_vector}"


# What each class of finding is, and the impact metrics normally accepted for
# it. Everything here except privileges required is a property of the class
# rather than of this particular target, and the report says so, because a
# number that looks measured but is not is worse than no number.
CLASSES = {
    "sqli": {
        "cwe": "CWE-89",
        "cwe_name": ("Improper Neutralization of Special Elements used in an "
                     "SQL Command"),
        "owasp": "A03:2021 Injection",
        # the database evaluates attacker input, so what is in the database is
        # reachable, and in the normal case so is writing to it
        "metrics": {"av": "N", "ac": "L", "ui": "N", "s": "U",
                    "c": "H", "i": "H", "a": "H"},
        "conventional": (
            "Confidentiality, integrity and availability are the impacts "
            "normally assigned to SQL injection. ProofScan proves the database "
            "evaluates injected input. It does not read the data out, write to "
            "the database, or take it offline, because a scanner that did those "
            "things to prove a point would be causing the damage it reports."
        ),
    },
    "xss": {
        "cwe": "CWE-79",
        "cwe_name": ("Improper Neutralization of Input During Web Page "
                     "Generation (Cross-site Scripting)"),
        "owasp": "A03:2021 Injection",
        # the script runs in the visitor's browser, which is a different
        # security context from the application, so the scope changes. somebody
        # has to load the page, so user interaction is required.
        "metrics": {"av": "N", "ac": "L", "ui": "R", "s": "C",
                    "c": "L", "i": "L", "a": "N"},
        "conventional": (
            "The usual metrics for cross-site scripting. Scope is Changed "
            "because the injected script runs in the browser rather than in the "
            "vulnerable application, and user interaction is Required because "
            "somebody has to load the page. ProofScan proves the script runs. "
            "It does not steal a session or act as the visitor."
        ),
    },
}


def score_finding(kind, needed_login):
    """Score one proved finding.

    needed_login is the single metric taken from the scan rather than from the
    class. If the scanner had to log in to reach the injection point then so
    does an attacker, so privileges required is Low rather than None.

    It is a simplification and the report says so. A reflected cross-site
    scripting bug behind a login can still be reached by somebody with no
    account at all, by sending the link to a person who has one.
    """
    spec = CLASSES.get(kind)
    if spec is None:
        return None

    metrics = dict(spec["metrics"])
    metrics["pr"] = "L" if needed_login else "N"

    score = base_score(**metrics)

    return Score(
        cvss_vector=vector_string(**metrics),
        cvss_score=score,
        severity=severity_of(score),
        cwe=spec["cwe"],
        cwe_name=spec["cwe_name"],
        owasp=spec["owasp"],
        observed={
            "PR": metrics["pr"],
            "why": ("the scanner had to log in to reach this point"
                    if needed_login else
                    "the point was reachable without logging in"),
        },
        conventional=spec["conventional"],
    )
