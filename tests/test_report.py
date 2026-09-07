"""Report tests.

Two things matter here. The first is that the numbers and the proofs in the
document are the ones the scan actually produced, because a report that quietly
rounds, drops or invents is worse than no report. The second is escaping, and it
is the one with teeth: this document prints working xss payloads by design and
then gets opened in a browser to make the pdf. A report that runs the exploit it
is reporting, on whoever opens it, is a real bug and not a hypothetical one.

No server needed. The pdf tests want chromium and skip without it.
"""
from pathlib import Path
from types import SimpleNamespace

import pytest

from proofscan.report import (ADVICE, TECHNIQUES, attempt_rows, default_path,
                              limitations, proof_rows, render_html,
                              severity_counts, techniques_used, write_pdf)
from samples import (LAB, boolean_confirmed, browser_confirmed, rejected,
                     report, timing_confirmed, unconfirmed)


@pytest.fixture(scope="module")
def chromium():
    """Skip rather than fail when there is no browser to print with."""
    from playwright.sync_api import sync_playwright
    try:
        with sync_playwright() as pw:
            pw.chromium.launch(headless=True).close()
    except Exception as e:
        pytest.skip(f"chromium not available: {e}")


# --- the proof, flattened -----------------------------------------------------

def labelled(rows):
    return dict(rows)


def test_a_true_false_proof_prints_both_payloads_and_the_bar_it_beat():
    rows = labelled(proof_rows(boolean_confirmed()))

    assert rows["Payload, true condition"] == "1' AND '1'='1"
    assert rows["Payload, false condition"] == "1' AND '1'='2"
    assert "4210 bytes" in rows["Response to true"]
    assert "0.9012" in rows["Similarity"]
    # the repeat is what separates a real difference from a fluctuation, so it
    # has to be in the document and not just in the decision
    assert "0.9008" in rows["Similarity"]
    assert "0.9995" in rows["The page's own noise"]


def test_a_timing_proof_prints_the_gap_and_the_ranges():
    rows = labelled(proof_rows(timing_confirmed()))

    assert "10120 ms against 119 ms" in rows["Median response time"]
    assert rows["Delay asked for"] == "2000 ms"
    assert rows["Samples"] == "20 of each"
    # the separation rule is the one that does the work, so say it plainly
    assert "10001 ms" in rows["Ranges"]
    assert "never overlap" in rows["Ranges"]


def test_a_timing_proof_does_not_claim_separation_it_did_not_have():
    finding = timing_confirmed()
    finding.evidence["proof"]["ranges_separated"] = False

    assert "never overlap" not in labelled(proof_rows(finding))["Ranges"]


def test_a_browser_proof_prints_what_was_sent_and_what_came_back():
    rows = labelled(proof_rows(browser_confirmed()))

    assert rows["Value sent"] == "t0ken"
    assert rows["Value the browser gave back"] == "t0ken"
    assert "window.__proofscan_xss" in rows["What it sets"]


def test_a_finding_with_no_proof_has_no_proof_rows():
    assert proof_rows(rejected()) == []
    assert proof_rows(unconfirmed()) == []


def test_what_was_tried_before_a_candidate_was_thrown_out():
    rows = attempt_rows(rejected())

    tried, happened = rows[0]
    assert "1' AND '1'='1" in tried and "1' AND '1'='2" in tried
    assert "no more different than the page is from itself" in happened
    assert "0.9999" in happened


def test_browser_attempts_flatten_to_the_single_payload():
    tried, happened = attempt_rows(browser_confirmed())[0]

    assert tried == "<svg onload=...>"
    assert happened == "nothing ran"


# --- the summary --------------------------------------------------------------

def test_severities_come_out_worst_first_with_the_empty_bands_dropped():
    counts = severity_counts(report().confirmed)

    assert counts == [("Critical", 2), ("Medium", 1)]


def test_only_the_techniques_that_were_used_are_explained():
    """Explaining a test that never ran invites a reader to assume it was run."""
    used = dict(techniques_used([browser_confirmed()]))

    assert list(used) == ["browser"]
    assert used["browser"] == TECHNIQUES["browser"]

    assert [name for name, _ in techniques_used(report().confirmed)] == [
        "boolean", "timing", "browser"]


def test_the_tally_counts_blind_findings_apart_from_the_rest():
    """The blind one was never a candidate, so folding it in would flatter the
    percentage."""
    tally = report().tally

    assert tally["candidates"] == 4
    assert tally["proved"] == 2        # the two the detector flagged
    assert tally["blind"] == 1         # the timing one it could not see
    assert tally["rejected"] == 1
    assert tally["removed_pct"] == 25.0


def test_safe_mode_is_admitted_in_the_limitations():
    assert any("safe mode" in note for note in limitations(report(safe_mode=True)))
    assert not any("safe mode" in note for note in limitations(report()))


def test_an_authenticated_scan_admits_the_privileges_simplification():
    notes = limitations(report(authenticated=True))

    assert any("Privileges Required" in note for note in notes)
    assert not any("Privileges Required" in note for note in limitations(report()))


def test_the_limitations_always_name_what_is_out_of_scope():
    notes = " ".join(limitations(report()))

    assert "DOM based" in notes
    assert "command injection" in notes.lower()


# --- the document itself ------------------------------------------------------

def test_the_report_cannot_run_the_payloads_it_prints():
    """The one that has teeth. See the note at the top of this file."""
    document = render_html(report([browser_confirmed()]))

    assert "<script>window.__proofscan_xss" not in document
    assert "&lt;script&gt;window.__proofscan_xss" in document
    # the template has no script tags of its own, so nothing at all should be
    # able to open one
    assert "<script" not in document
    # and this is not passing because the document came out empty
    assert "<style>" in document


def test_an_attribute_breaking_payload_cannot_break_out_of_the_document():
    """The payload has to be readable, so the text stays. The quotes that make
    it dangerous are what has to go."""
    finding = browser_confirmed()
    finding.evidence["proof"]["payload"] = '" onfocus=alert(1) autofocus x="'

    document = render_html(report([finding]))

    assert "&#34; onfocus=alert(1) autofocus x=&#34;" in document
    assert '" onfocus=alert(1) autofocus x="' not in document


def test_the_document_carries_the_target_and_when_it_ran():
    document = render_html(report())

    assert LAB in document
    assert "07 September 2026, 10:00 UTC" in document


def test_the_headline_numbers_are_the_scan_s_own():
    scan = report()
    document = render_html(scan)
    tally = scan.tally

    for number in (tally["candidates"], tally["rejected"]):
        assert f'<div class="n">{number}</div>' in document
    assert '<div class="n">25%</div>' in document


def test_every_confirmed_finding_is_written_up_with_its_score():
    document = render_html(report())

    assert "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" in document
    assert "CWE-89" in document
    assert "CWE-79" in document
    assert "A03:2021 Injection" in document
    # the sentence saying what the score does not cover
    assert "does not read the data out" in document


def test_the_fix_advice_is_there_for_both_classes():
    document = render_html(report())

    assert ADVICE["sqli"][:60] in document
    assert ADVICE["xss"][:60] in document


def test_rejected_candidates_are_written_up_with_what_was_tried():
    document = render_html(report())

    assert "Candidates thrown out" in document
    assert f"{LAB}/safe-product" in document
    assert "no true/false pair beat the page" in document
    assert "0.9999" in document


def test_an_unproved_finding_is_neither_confirmed_nor_dismissed():
    document = render_html(report([unconfirmed()]))

    assert "Could not be proved either way" in document
    assert "chromium is not installed" in document


def test_the_appendix_lists_what_was_reached_and_what_was_left_alone():
    document = render_html(report())

    assert f"{LAB}/logout" in document
    assert "Left alone on purpose" in document


def test_a_clean_target_still_produces_a_report():
    """Nothing found is a result, and the document has to say so rather than
    coming out half rendered."""
    document = render_html(report([], candidates=0))

    assert "Nothing was proved on this target" in document
    assert "Nothing was flagged by stage one" in document
    assert '<div class="n">0%</div>' in document


def test_the_default_filename_carries_the_scan_id():
    assert default_path(SimpleNamespace(id=7)) == Path("reports") / "proofscan-scan-7.pdf"
    # a report that was never stored has no id, so it gets a generic name
    assert default_path(report()).name == "proofscan-report.pdf"


# --- printing it --------------------------------------------------------------

def test_the_pdf_is_a_real_pdf(tmp_path, chromium):
    path, html_path = write_pdf(report(), tmp_path / "out.pdf")

    data = path.read_bytes()
    assert data.startswith(b"%PDF")
    assert data.rstrip().endswith(b"%%EOF")
    assert len(data) > 10000
    assert html_path is None


def test_the_html_can_be_kept_beside_the_pdf(tmp_path, chromium):
    _, html_path = write_pdf(report(), tmp_path / "out.pdf", keep_html=True)

    assert html_path == tmp_path / "out.html"
    assert "Confirmed findings" in html_path.read_text(encoding="utf-8")


def test_the_reports_folder_is_made_if_it_is_not_there(tmp_path, chromium):
    path, _ = write_pdf(report(), tmp_path / "new" / "deep" / "out.pdf")

    assert path.exists()
