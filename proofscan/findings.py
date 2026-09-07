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
