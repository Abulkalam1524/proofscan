"""The timing rules, checked against made up samples.

No server here on purpose. The decision is plain arithmetic once the samples are
in, so handing it numbers directly is quicker than running a scan, and it lets
me build the awkward cases exactly instead of waiting for one to show up. A
server that is randomly slow is the case that matters, and hoping /jitter
misbehaves during a test run is not a test.
"""
import random

from proofscan.validators.sqli_timing import DELAY_SECONDS, MIN_SHARE, looks_delayed


def jittery(count, seed, slow_one_in=6, normal_ms=8.0, slow_ms=1000.0):
    """Samples from a server like /jitter: quick, apart from when it is not."""
    rng = random.Random(seed)
    return [slow_ms if rng.random() < 1 / slow_one_in else normal_ms + rng.random() * 4
            for _ in range(count)]


def test_confirms_a_real_delay():
    """Every true sample waits, no false sample does. This is the real thing."""
    true_ms = [2004, 2011, 2002, 2019, 2007, 2003, 2026, 2009, 2005, 2013]
    false_ms = [7, 9, 6, 12, 8, 7, 10, 6, 9, 8]

    delayed, stats = looks_delayed(true_ms, false_ms)

    assert delayed
    assert stats["ranges_separated"]
    assert stats["median_gap_ms"] >= DELAY_SECONDS * 1000 * MIN_SHARE


def test_rejects_a_server_that_is_randomly_slow():
    """The /jitter case, and the reason the whole thing takes samples.

    Random slowness lands in both sets, so the ranges cross and the medians stay
    together. A scanner that trusted one measurement would report a bug here.
    """
    for seed in range(20):
        true_ms = jittery(10, seed=seed)
        false_ms = jittery(10, seed=seed + 100)

        delayed, _ = looks_delayed(true_ms, false_ms)

        assert not delayed, f"random slowness read as a delay, seed {seed}"


def test_rejects_one_slow_sample_among_fast_ones():
    """A single stall is not proof, however big it is."""
    true_ms = [8, 9, 7, 5000, 6, 11, 8, 7, 9, 10]
    false_ms = [7, 9, 6, 12, 8, 7, 10, 6, 9, 8]

    delayed, _ = looks_delayed(true_ms, false_ms)

    assert not delayed


def test_rejects_when_one_true_sample_came_back_fast():
    """Nine waits and one that did not is not a sleep, it is something else.

    The median alone would pass this. The separation rule is what catches it.
    """
    true_ms = [2004, 2011, 2002, 9, 2007, 2003, 2026, 2009, 2005, 2013]
    false_ms = [7, 9, 6, 12, 8, 7, 10, 6, 9, 8]

    delayed, stats = looks_delayed(true_ms, false_ms)

    assert stats["median_gap_ms"] >= DELAY_SECONDS * 1000 * MIN_SHARE
    assert not stats["ranges_separated"]
    assert not delayed


def test_rejects_a_server_that_is_just_slow_all_round():
    """Both sides slow means the app is slow, not that the condition ran."""
    true_ms = [2050, 2120, 2080, 2010, 2200, 2090, 2030, 2160, 2070, 2110]
    false_ms = [2040, 2130, 2060, 2020, 2190, 2100, 2050, 2140, 2080, 2120]

    delayed, _ = looks_delayed(true_ms, false_ms)

    assert not delayed


def test_rejects_a_delay_shorter_than_the_one_we_asked_for():
    """Consistent, separated, but only a fraction of the sleep. Not ours."""
    true_ms = [300, 311, 302, 319, 307, 303, 326, 309, 305, 313]
    false_ms = [7, 9, 6, 12, 8, 7, 10, 6, 9, 8]

    delayed, stats = looks_delayed(true_ms, false_ms)

    assert stats["ranges_separated"]
    assert not delayed


def test_no_samples_proves_nothing():
    assert looks_delayed([], []) == (False, {})
    assert looks_delayed([2000], []) == (False, {})
