"""What a finding looks like once the detector and the validator are done with it."""
from dataclasses import dataclass, field
from enum import Enum


class Verdict(str, Enum):
    CONFIRMED = "CONFIRMED"        # proved it is real
    UNCONFIRMED = "UNCONFIRMED"    # could not prove it either way
    REJECTED = "REJECTED"          # proved it is not there, false alarm


@dataclass
class Finding:
    kind: str                      # "sqli", "xss", ...
    point: object                  # the InjectionPoint it was found at
    verdict: Verdict
    reason: str                    # short text explaining the verdict
    evidence: dict = field(default_factory=dict)
    # cvss and cwe, filled in only once a finding is proved. scoring something
    # the scanner could not prove would be putting a decimal point on a guess.
    score: object = None
    # pictures of the proof, each {"label": ..., "png": bytes}. kept out of the
    # evidence dict because that is json, and a png is not text.
    screenshots: list = field(default_factory=list)

    def __str__(self):
        return f"[{self.verdict.value:11}] {self.kind:5} {self.point}  {self.reason}"


class FindingsView:
    """The three verdict lists, shared by live and stored scans so both print the same."""
    findings = ()
    candidates = 0

    def by_verdict(self, verdict):
        return [f for f in self.findings if f.verdict is verdict]

    @property
    def confirmed(self):
        """Worst first, because that is the order somebody fixes them in."""
        return sorted(self.by_verdict(Verdict.CONFIRMED),
                      key=lambda f: (-(f.score.cvss_score if f.score else 0.0),
                                     f.point.url, f.point.param))

    @property
    def unconfirmed(self):
        return self.by_verdict(Verdict.UNCONFIRMED)

    @property
    def rejected(self):
        return self.by_verdict(Verdict.REJECTED)

    @property
    def tally(self):
        """The funnel: suspected, proved, thrown out.

        Blind finds (timing test only) are counted apart so they do not inflate the percentage.
        """
        from_detector = [f for f in self.confirmed
                         if f.evidence.get("detector_reason")]
        removed = len(self.rejected)

        return {
            "candidates": self.candidates,
            "proved": len(from_detector),
            "blind": len(self.confirmed) - len(from_detector),
            "rejected": removed,
            "removed_pct": (removed / self.candidates * 100) if self.candidates else 0.0,
        }
