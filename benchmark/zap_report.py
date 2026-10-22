"""Read a ZAP json report into one alert per url and parameter, like ProofScan.

Classes are matched by CWE (89 and 79), not by name, because ZAP has
several differently named SQL injection rules.
"""
import json
from dataclasses import dataclass
from urllib.parse import urlparse

# the two classes ProofScan v1 covers, which are the only ones either tool can
# fairly be scored on here
CWE_TO_KIND = {"89": "sqli", "79": "xss"}

RISKS = {"0": "Informational", "1": "Low", "2": "Medium", "3": "High"}
CONFIDENCES = {"0": "False Positive", "1": "Low", "2": "Medium", "3": "High",
               "4": "Confirmed"}


def normalise_path(url):
    """Lower case path, no query, no trailing slash, so both tools' urls match."""
    path = urlparse(url).path.lower()
    path = path.rstrip("/")
    return path or "/"


@dataclass(frozen=True)
class ZapAlert:
    kind: str          # "sqli", "xss", or None when outside the compared classes
    name: str
    cwe: str
    risk: str
    confidence: str
    method: str
    path: str
    param: str
    uri: str = ""
    attack: str = ""
    evidence: str = ""

    @property
    def key(self):
        return (self.kind, self.path, self.param)


def _alerts_in(site):
    """ZAP names the alert list differently depending on the report template."""
    return site.get("alerts") or site.get("alert") or []


def parse(path_or_text):
    """Every instance in a ZAP report as a flat list. Takes a path or the json text.

    Instances with no parameter are kept, with an empty param.
    """
    text = path_or_text
    try:
        if not str(path_or_text).lstrip().startswith("{"):
            with open(path_or_text, encoding="utf-8") as handle:
                text = handle.read()
    except OSError:
        raise

    report = json.loads(text)

    found = []
    seen = set()

    for site in report.get("site", []):
        for alert in _alerts_in(site):
            cwe = str(alert.get("cweid", "")).strip()
            kind = CWE_TO_KIND.get(cwe)
            name = alert.get("name") or alert.get("alert") or ""
            risk = RISKS.get(str(alert.get("riskcode", "")).strip(),
                             alert.get("riskdesc", ""))
            confidence = CONFIDENCES.get(str(alert.get("confidence", "")).strip(), "")

            for instance in alert.get("instances", [{}]):
                uri = instance.get("uri", "")
                entry = ZapAlert(
                    kind=kind,
                    name=name,
                    cwe=cwe,
                    risk=risk,
                    confidence=confidence,
                    method=(instance.get("method") or "GET").upper(),
                    path=normalise_path(uri),
                    param=instance.get("param", "") or "",
                    uri=uri,
                    attack=instance.get("attack", "") or "",
                    evidence=instance.get("evidence", "") or "",
                )

                # one url and parameter reported by three different sql
                # injection rules is one finding for a person to check, not
                # three, and counting it three times would flatter ProofScan
                fingerprint = (entry.kind, entry.name, entry.path, entry.param)
                if fingerprint in seen:
                    continue
                seen.add(fingerprint)
                found.append(entry)

    return found


def in_scope(alerts):
    """Only the alerts in the two classes being compared."""
    return [a for a in alerts if a.kind is not None]


def out_of_scope(alerts):
    """Everything else ZAP reported. Counted, not thrown away."""
    return [a for a in alerts if a.kind is None]
