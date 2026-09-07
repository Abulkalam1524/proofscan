"""The report. One stored scan, rendered to html and printed to pdf.

It reads a scan out of the evidence store and never runs one itself. That is
deliberate rather than convenient: a report is a claim about what was proved,
and if it could go and re-test the target while printing, the document and the
evidence behind it would be two different things. Everything in here comes from
a row in the file.

**Autoescaping is not optional.** This document prints attacker-controlled
strings by design. Every confirmed cross site scripting finding contains a
payload written to run in a browser, and the report gets opened in a browser to
turn it into a pdf. Building the html by hand and forgetting one escape would
mean a security report that runs the exploit it is reporting, on whoever opens
it. Jinja2 with autoescape on makes that the default instead of something to
remember, which is the only reason a template engine is worth the dependency for
one document.

WeasyPrint would have been the obvious way to make the pdf and is ruled out: it
needs GTK on windows and does not install. Chromium is already here for the xss
validator, and `page.pdf()` is the same renderer that draws the html, so what
prints is what the browser showed.
"""
from datetime import datetime, timedelta
from html import escape
from pathlib import Path

from jinja2 import Environment, FileSystemLoader, select_autoescape
from playwright.sync_api import sync_playwright

from . import __version__

TEMPLATES = Path(__file__).parent / "templates"
DEFAULT_DIR = Path("reports")

PAGE_TIMEOUT_MS = 30000

SEVERITY_ORDER = ["Critical", "High", "Medium", "Low", "None"]

# What each technique establishes, and what it does not. This goes in the
# methodology section so a reader can judge the proof rather than take the word
# CONFIRMED on trust.
TECHNIQUES = {
    "boolean": (
        "A condition that is always true and one that is always false are sent "
        "in the same place, identical to each other in every way except the "
        "condition. If the two responses come back meaningfully different, the "
        "database evaluated the input rather than storing it as text. How "
        "different they have to be is measured against how much the page "
        "disagrees with itself when asked the same question three times, so a "
        "page that changes on its own sets its own bar. Anything that looks "
        "like a hit is asked a second time, because a real difference repeats."
    ),
    "timing": (
        "For injection that changes nothing on the page. Two payloads both "
        "carry a delay, one behind a true condition and one behind a false "
        "one, so they are the same length and take the same path through the "
        "parser. Confirmation needs both of two things: the medians apart by "
        "most of the delay asked for, and the slowest response to the false "
        "condition still quicker than the fastest response to the true one. "
        "Random slowness lands in both sets and makes those ranges overlap. A "
        "real delay never does."
    ),
    "browser": (
        "Reflection is not execution. A page can hand input straight back and "
        "still be safe, because it escaped the brackets or because a Content-"
        "Security-Policy header stops the script running. So the response body "
        "is not read at all. A payload sets one variable to a value generated "
        "for that single attempt, the page is loaded in headless Chromium, and "
        "the browser is asked what that variable holds. Nothing else can set "
        "it."
    ),
}

# Generic remediation for the class, and labelled as generic. ProofScan proves
# where the bug is, not how this particular codebase should be changed.
ADVICE = {
    "sqli": (
        "Use parameterised queries or prepared statements everywhere, so that "
        "input is passed to the database as a value and never assembled into "
        "the statement text. Escaping and blocklists are worked around "
        "routinely and are not a substitute. Where a query has to take an "
        "identifier such as a column or table name, check it against a fixed "
        "list of permitted values rather than escaping it. Give the "
        "application's database account only the rights it needs, so that an "
        "injection that is missed costs less."
    ),
    "xss": (
        "Encode output for the context it lands in: html body, attribute, "
        "javascript and url each need different treatment, and a template "
        "engine that escapes by default handles most of it. Validate input on "
        "the way in as well, but treat that as a second line rather than the "
        "fix. Add a Content-Security-Policy that refuses inline scripts, which "
        "limits the damage of anything that gets through, and set HttpOnly on "
        "session cookies so a script that does run cannot read them."
    ),
}


def _moment(value):
    """A timestamp a person can read, from either a datetime or a stored string."""
    if not value:
        return "unknown"

    moment = value if isinstance(value, datetime) else datetime.fromisoformat(value)
    shown = moment.strftime("%d %B %Y, %H:%M")
    return f"{shown} UTC" if moment.utcoffset() in (None, timedelta(0)) else shown


def _duration(seconds):
    seconds = int(round(seconds or 0))
    if seconds < 60:
        return f"{seconds}s"
    return f"{seconds // 60}m {seconds % 60:02d}s"


def proof_rows(finding):
    """The proof behind one confirmed finding, flattened for printing.

    The three techniques prove different things with different numbers, so the
    branching happens here. A template full of "if the technique is timing" is a
    template nobody can check, and this part is the one worth checking.
    """
    proof = finding.evidence.get("proof")
    if not proof:
        return []

    technique = finding.evidence.get("technique")

    if technique == "timing":
        ranges = (
            f"fastest response to the true condition {proof['true_min_ms']:.0f} ms, "
            f"slowest to the false one {proof['false_max_ms']:.0f} ms"
        )
        if proof.get("ranges_separated"):
            ranges += ", so the two never overlap"
        return [
            ("Payload, true condition", proof["true_payload"]),
            ("Payload, false condition", proof["false_payload"]),
            ("Median response time",
             f"{proof['true_median_ms']:.0f} ms against "
             f"{proof['false_median_ms']:.0f} ms, a gap of "
             f"{proof['median_gap_ms']:.0f} ms"),
            ("Delay asked for", f"{proof['delay_asked_ms']:.0f} ms"),
            ("Ranges", ranges),
            ("Samples", f"{proof['samples']} of each"),
        ]

    if technique == "browser":
        return [
            ("Payload", proof["payload"]),
            ("What it sets",
             f"window.{proof['variable']}, to a value generated for this one "
             f"attempt and nothing else"),
            ("Value sent", proof["token"]),
            ("Value the browser gave back", proof["read_back"]),
        ]

    return [
        ("Payload, true condition", proof["true_payload"]),
        ("Payload, false condition", proof["false_payload"]),
        ("Response to true",
         f"HTTP {proof['true_status']}, {proof['true_length']} bytes"),
        ("Response to false",
         f"HTTP {proof['false_status']}, {proof['false_length']} bytes"),
        ("Similarity",
         f"{proof['similarity']:.4f}, and {proof['repeat_similarity']:.4f} when "
         f"the same pair was sent again"),
        ("The page's own noise",
         f"it scores {proof['noise_floor']:.4f} against itself, so a pair had to "
         f"come in under {proof['threshold']:.4f} to count"),
    ]


def attempt_rows(finding):
    """What was tried before a candidate was thrown out.

    The false alarm count is the number this project is judged on, and a number
    like that is worth nothing without the work behind it shown. This is the
    half a scanner normally discards.
    """
    rows = []

    for attempt in finding.evidence.get("attempts", []):
        if "true_payload" in attempt:
            tried = f"{attempt['true_payload']}   /   {attempt['false_payload']}"
        else:
            tried = attempt.get("payload", "")

        happened = attempt.get("result", "")
        if "similarity" in attempt:
            happened = f"{happened} (similarity {attempt['similarity']:.4f})"

        rows.append((tried, happened))

    return rows


def severity_counts(findings):
    """How many of each severity, worst band first, skipping the empty ones."""
    counts = {}
    for finding in findings:
        if finding.score:
            counts[finding.score.severity] = counts.get(finding.score.severity, 0) + 1

    return [(band, counts[band]) for band in SEVERITY_ORDER if counts.get(band)]


def techniques_used(findings):
    """The techniques this scan actually leaned on, in a fixed order.

    Only what was used. Explaining a test that never ran pads the methodology
    section and invites a reader to assume it was applied.
    """
    used = {f.evidence.get("technique") for f in findings}
    return [(name, text) for name, text in TECHNIQUES.items() if name in used]


def limitations(scan):
    """Everything this report is not claiming, said in the report itself.

    A reader who has to work out the gaps for themselves will assume there are
    none. Every one of these is a known edge of the tool rather than a caveat
    added for safety.
    """
    notes = [
        "Only SQL injection and cross site scripting were looked for. Command "
        "injection, file inclusion, insecure direct object references, cross "
        "site request forgery and open redirects are outside this version's "
        "scope, and a page carrying one of those would be reported clean here.",

        "DOM based cross site scripting is not detected. The check looks at "
        "what the server sends, and a payload handled entirely in javascript "
        "never appears there.",

        "Pages that change how the target behaves were left alone on purpose: "
        "logout, setup, and security or settings pages. They are listed in the "
        "appendix. A scan that alters what it is measuring proves nothing "
        "about what it measured afterwards.",

        "Nothing here was proved by reading a version number or a banner. "
        "Every confirmed finding was demonstrated against the running "
        "application.",
    ]

    if scan.safe_mode:
        notes.insert(0,
            "This scan ran in safe mode, so the timing tests were skipped. "
            "Blind SQL injection, where the page never changes, cannot be "
            "found without them and would be reported as a false alarm.")

    if scan.authenticated:
        notes.append(
            "The scan was authenticated, so Privileges Required is scored as "
            "Low on every finding. That is a simplification: a reflected cross "
            "site scripting bug behind a login can still be reached by someone "
            "with no account, by sending the link to a person who has one.")

    return notes


def build_context(scan, generated_at=None):
    confirmed = scan.confirmed

    return {
        "scan": scan,
        "version": __version__,
        "generated": _moment(generated_at or datetime.now().astimezone()),
        "started": _moment(scan.started_at),
        "duration": _duration(scan.duration_seconds),
        "tally": scan.tally,
        "severities": severity_counts(confirmed),
        "techniques": techniques_used(confirmed),
        "limitations": limitations(scan),
        "confirmed": [
            {
                "finding": finding,
                "proof_rows": proof_rows(finding),
                "advice": ADVICE.get(finding.kind, ""),
            }
            for finding in confirmed
        ],
        "rejected": [
            {"finding": finding, "attempt_rows": attempt_rows(finding)}
            for finding in scan.rejected
        ],
        "unconfirmed": scan.unconfirmed,
    }


def _environment():
    return Environment(
        loader=FileSystemLoader(TEMPLATES),
        # the one setting that matters here, see the note at the top of the file
        autoescape=select_autoescape(default_for_string=True, default=True),
        trim_blocks=True,
        lstrip_blocks=True,
    )


def render_html(scan, generated_at=None):
    template = _environment().get_template("report.html")
    return template.render(**build_context(scan, generated_at))


def default_path(scan):
    scan_id = getattr(scan, "id", None)
    name = f"proofscan-scan-{scan_id}.pdf" if scan_id else "proofscan-report.pdf"
    return DEFAULT_DIR / name


def write_pdf(scan, path=None, keep_html=False, generated_at=None):
    """Render the scan and print it. Returns where the pdf went."""
    path = Path(path) if path else default_path(scan)
    path.parent.mkdir(parents=True, exist_ok=True)

    document = render_html(scan, generated_at)

    html_path = None
    if keep_html:
        html_path = path.with_suffix(".html")
        html_path.write_text(document, encoding="utf-8")

    # the target goes in the running header, escaped, because it is a url
    # somebody handed us on the command line
    header = (
        '<div style="font-size:7.5pt;color:#8a8a8a;width:100%;padding:0 14mm;'
        'font-family:Segoe UI,Helvetica,Arial,sans-serif;">'
        f'ProofScan &nbsp;&middot;&nbsp; {escape(scan.target)}</div>'
    )
    footer = (
        '<div style="font-size:7.5pt;color:#8a8a8a;width:100%;padding:0 14mm;'
        'font-family:Segoe UI,Helvetica,Arial,sans-serif;text-align:right;">'
        '<span class="pageNumber"></span> of <span class="totalPages"></span></div>'
    )

    with sync_playwright() as pw:
        browser = pw.chromium.launch(headless=True)
        try:
            page = browser.new_page()
            # set_content rather than a file url, so there is no temporary file
            # to leave behind and nothing on disk between rendering and printing
            page.set_content(document, wait_until="load", timeout=PAGE_TIMEOUT_MS)
            page.emulate_media(media="print")
            page.pdf(
                path=str(path),
                format="A4",
                print_background=True,
                display_header_footer=True,
                header_template=header,
                footer_template=footer,
                margin={"top": "18mm", "bottom": "16mm",
                        "left": "14mm", "right": "14mm"},
            )
        finally:
            browser.close()

    return path, html_path
