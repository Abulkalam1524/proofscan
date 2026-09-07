"""CVSS v3.1 arithmetic, checked against vectors with published scores.

The formula is not something to take on trust. It has a scope dependent
privileges table, two different impact equations, and a rounding rule of its
own, and getting any of them slightly wrong produces scores that look plausible
and are wrong. So the arithmetic is checked against vectors whose scores are
published, rather than against what this code happens to produce.

No server needed for any of this.
"""
import pytest

from proofscan.findings import Verdict
from proofscan.scoring import (CLASSES, base_score, roundup, score_finding,
                               severity_of, vector_string)

# vector, expected base score. these are published values, not outputs of this
# module, which is the entire point of having them here.
REFERENCE = [
    (dict(av="N", ac="L", pr="N", ui="N", s="U", c="H", i="H", a="H"), 9.8),
    (dict(av="N", ac="L", pr="L", ui="N", s="U", c="H", i="H", a="H"), 8.8),
    (dict(av="N", ac="L", pr="N", ui="R", s="C", c="L", i="L", a="N"), 6.1),
    (dict(av="N", ac="L", pr="L", ui="R", s="C", c="L", i="L", a="N"), 5.4),
    (dict(av="N", ac="L", pr="N", ui="N", s="U", c="N", i="N", a="H"), 7.5),
    (dict(av="N", ac="L", pr="N", ui="N", s="U", c="H", i="N", a="N"), 7.5),
    (dict(av="L", ac="L", pr="L", ui="N", s="U", c="H", i="H", a="H"), 7.8),
    # someone has to open it first, which costs 1.0 against the 9.8 above
    (dict(av="N", ac="L", pr="N", ui="R", s="U", c="H", i="H", a="H"), 8.8),
    # the maximum a base score can reach: everything high and the scope changes
    (dict(av="N", ac="L", pr="N", ui="N", s="C", c="H", i="H", a="H"), 10.0),
]


@pytest.mark.parametrize("metrics,expected", REFERENCE)
def test_matches_published_scores(metrics, expected):
    assert base_score(**metrics) == expected


def test_no_impact_scores_zero():
    """Nothing broken, nothing to score."""
    assert base_score(av="N", ac="L", pr="N", ui="N", s="U",
                      c="N", i="N", a="N") == 0.0


def test_roundup_always_goes_up():
    """The spec rounds up to one decimal, it never rounds down."""
    assert roundup(4.001) == 4.1
    assert roundup(4.0) == 4.0
    assert roundup(0.0) == 0.0
    assert roundup(9.91) == 10.0


def test_severity_bands():
    assert severity_of(0.0) == "None"
    assert severity_of(3.9) == "Low"
    assert severity_of(4.0) == "Medium"
    assert severity_of(6.9) == "Medium"
    assert severity_of(7.0) == "High"
    assert severity_of(8.9) == "High"
    assert severity_of(9.0) == "Critical"
    assert severity_of(10.0) == "Critical"


def test_vector_string_is_the_standard_format():
    v = vector_string(av="N", ac="L", pr="N", ui="N", s="U", c="H", i="H", a="H")
    assert v == "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"


def test_sqli_unauthenticated_is_critical():
    s = score_finding("sqli", needed_login=False)
    assert s.cvss_score == 9.8
    assert s.severity == "Critical"
    assert s.cwe == "CWE-89"
    assert "PR:N" in s.cvss_vector


def test_sqli_behind_a_login_scores_lower():
    """Needing an account to reach it is worth something, and the scanner knows
    whether it needed one, so that metric is observed rather than assumed."""
    open_door = score_finding("sqli", needed_login=False)
    behind_login = score_finding("sqli", needed_login=True)

    assert behind_login.cvss_score < open_door.cvss_score
    assert behind_login.cvss_score == 8.8
    assert "PR:L" in behind_login.cvss_vector
    assert behind_login.observed["PR"] == "L"


def test_xss_scores_medium_and_changes_scope():
    s = score_finding("xss", needed_login=False)
    assert s.cvss_score == 6.1
    assert s.severity == "Medium"
    assert s.cwe == "CWE-79"
    # the script runs in the browser, not in the vulnerable app, so the scope
    # changes, and somebody has to load the page
    assert "S:C" in s.cvss_vector
    assert "UI:R" in s.cvss_vector


def test_xss_behind_a_login_scores_lower():
    assert score_finding("xss", needed_login=True).cvss_score == 5.4


def test_every_class_maps_to_a_cwe_and_an_owasp_category():
    for kind, spec in CLASSES.items():
        assert spec["cwe"].startswith("CWE-")
        assert spec["cwe_name"]
        assert spec["owasp"].startswith("A")
        assert spec["conventional"], f"{kind} should say what it did not prove"


def test_an_unknown_class_is_not_given_a_number():
    """Better no score than a made up one."""
    assert score_finding("something-new", needed_login=False) is None


def test_the_score_says_which_metric_came_from_the_scan():
    """The report has to be able to separate what was measured from what is
    conventional for the class, or the number looks more measured than it is."""
    s = score_finding("sqli", needed_login=True)
    assert s.observed["PR"] == "L"
    assert "log in" in s.observed["why"]
    assert "does not" in s.conventional.lower() or "not" in s.conventional.lower()
