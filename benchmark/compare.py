"""Score ProofScan (verification off and on) and ZAP against one answer key.

Only SQL injection and XSS are scored. ZAP's alerts in other classes are
counted and printed beside the table, not dropped.
"""
from dataclasses import dataclass, field

from .zap_report import normalise_path


@dataclass(frozen=True)
class Reported:
    """One thing a tool said, reduced to the part that can be compared."""
    kind: str
    path: str
    param: str
    detail: str = ""

    @property
    def key(self):
        return (self.kind, self.path, self.param)

    def __str__(self):
        return f"{self.path} [{self.param}] {self.kind}"


@dataclass
class ToolScore:
    tool: str
    short: str = ""          # column heading, the full name does not fit
    note: str = ""
    reported: list = field(default_factory=list)
    hits: list = field(default_factory=list)          # real, and reported
    traps: list = field(default_factory=list)         # a documented trap, reported
    unlisted: list = field(default_factory=list)      # reported, not in the key
    missed: list = field(default_factory=list)        # real, not reported

    @property
    def false_alarms(self):
        """A trap and an unlisted alert both cost a person the same time."""
        return self.traps + self.unlisted

    @property
    def precision(self):
        found = len(self.hits) + len(self.false_alarms)
        return len(self.hits) / found if found else 0.0

    @property
    def recall(self):
        real = len(self.hits) + len(self.missed)
        return len(self.hits) / real if real else 0.0

    @property
    def f1(self):
        p, r = self.precision, self.recall
        return 2 * p * r / (p + r) if (p + r) else 0.0


@dataclass
class Comparison:
    key: object
    tools: list = field(default_factory=list)
    zap_other_classes: int = 0

    def tool(self, name):
        for score in self.tools:
            if score.tool == name:
                return score
        raise KeyError(name)


def score(tool, reported, key, note="", short=""):
    """One tool against the answer key."""
    reported = _dedupe(reported)
    by_key = {r.key: r for r in reported}

    result = ToolScore(tool=tool, short=short or tool, note=note,
                       reported=reported)

    for item in reported:
        entry = key.lookup(item.key)
        if entry is None:
            result.unlisted.append(item)
        elif entry.real:
            result.hits.append(entry)
        else:
            result.traps.append(entry)

    for entry in key.real:
        if entry.key not in by_key:
            result.missed.append(entry)

    return result


def _dedupe(reported):
    seen = {}
    for item in reported:
        seen.setdefault(item.key, item)
    return list(seen.values())


def from_zap(alerts):
    """ZAP's in-scope alerts, as comparable items."""
    return [
        Reported(kind=a.kind, path=a.path, param=a.param,
                 detail=f"{a.name} ({a.risk} risk, {a.confidence} confidence)")
        for a in alerts if a.kind is not None
    ]


def from_detector(scan):
    """What stage 1 flagged, before verification. Blind finds it never saw are left out."""
    return [
        Reported(kind=f.kind, path=normalise_path(f.point.url),
                 param=f.point.param,
                 detail=f.evidence.get("detector_reason", ""))
        for f in scan.findings
        if f.evidence.get("detector_reason")
    ]


def from_confirmed(scan):
    """What ProofScan could actually prove."""
    return [
        Reported(kind=f.kind, path=normalise_path(f.point.url),
                 param=f.point.param, detail=f.reason)
        for f in scan.confirmed
    ]


def run(scan, zap_alerts, key):
    """The three rows."""
    in_scope = [a for a in zap_alerts if a.kind is not None]

    return Comparison(
        key=key,
        zap_other_classes=len(zap_alerts) - len(in_scope),
        tools=[
            score("ProofScan, verification off", from_detector(scan), key,
                  "stage one only, what a scanner that does not check itself "
                  "would report", short="stage 1"),
            score("ProofScan, verification on", from_confirmed(scan), key,
                  "only what stage two proved", short="verified"),
            score("OWASP ZAP", from_zap(in_scope), key,
                  "active scan, alerts in the two compared classes",
                  short="ZAP"),
        ],
    )


def format_table(comparison):
    key = comparison.key
    lines = [
        f"Benchmark: {key.description}",
        "Compared on SQL injection and cross site scripting only.",
        f"Answer key: {len(key.real)} real vulnerabilities, "
        f"{len(key.traps)} documented traps.",
        "",
        f"{'':32}{'alerts':>7}{'correct':>9}{'false':>7}{'missed':>8}"
        f"{'precision':>11}{'recall':>8}",
    ]

    for tool in comparison.tools:
        lines.append(
            f"{tool.tool:32}{len(tool.reported):>7}{len(tool.hits):>9}"
            f"{len(tool.false_alarms):>7}{len(tool.missed):>8}"
            f"{tool.precision:>11.2f}{tool.recall:>8.2f}"
        )

    if comparison.zap_other_classes:
        lines += [
            "",
            f"ZAP reported {comparison.zap_other_classes} further alerts in "
            f"classes ProofScan does not look for.",
            "Those are outside this comparison and are not counted against "
            "either tool.",
        ]

    return "\n".join(lines)


def format_matrix(comparison):
    """Every entry in the answer key, and what each tool said about it."""
    columns = [t.short for t in comparison.tools]
    said = [{r.key for r in t.reported} for t in comparison.tools]

    width = max(len(f"{e.path} [{e.param}]") for e in comparison.key.entries) + 2
    lines = [
        f"{'':{width}}{'kind':6}{'truth':7}" + "".join(f"{c:>12}" for c in columns)
    ]

    for entry in comparison.key.entries:
        where = f"{entry.path} [{entry.param}]"
        truth = "REAL" if entry.real else "trap"
        marks = "".join(f"{('yes' if entry.key in s else '.'):>12}" for s in said)
        lines.append(f"{where:{width}}{entry.kind:6}{truth:7}{marks}")

    unlisted = []
    for tool in comparison.tools:
        for item in tool.unlisted:
            unlisted.append(f"  {tool.tool}: {item}  {item.detail}")

    if unlisted:
        lines += [
            "",
            "Reported but not in the answer key. Counted as false alarms, and "
            "worth checking by hand,",
            "because a key written by a person is never complete:",
        ] + unlisted

    return "\n".join(lines)
