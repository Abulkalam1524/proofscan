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

    def __str__(self):
        return f"[{self.verdict.value:11}] {self.kind:5} {self.point}  {self.reason}"


class FindingsView:
    """The three verdict buckets over a list of findings.

    Shared by the live scan report and by a scan loaded back out of the evidence
    store, so both sort and print identically. If the stored copy cannot produce
    the same output as the live one, the store lost something.
    """
    findings = ()

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
