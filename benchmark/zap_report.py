"""Read an OWASP ZAP json report and pull out the alerts worth comparing.

ZAP reports one alert per rule with a list of instances under it, and the
instance is the part that names a url and a parameter, which is the level
ProofScan works at. So one ZAP alert covering four parameters becomes four
comparable alerts here, deduplicated, the same way ProofScan reports one finding
per injection point.

Classes are decided by CWE id rather than by the alert's name. ZAP has several
rules that all mean sql injection ("SQL Injection", "SQL Injection - MySQL",
"SQL Injection - Hypersonic SQL") and matching on names would mean chasing that
list forever. CWE-89 and CWE-79 do not move.
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
    """Just the path, lower case, no trailing slash, no query.

    Both tools have to be reduced to the same shape before anything can be
    matched. ZAP reports the full uri with the query still on it, ProofScan
    stores the url without one, and DVWA is inconsistent about trailing slashes.
    """
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
    """Every instance in a ZAP json report, as a flat list of ZapAlert.

    Takes a path or the json text itself. Instances with no parameter are kept
    with an empty param: a lot of ZAP's rules are about the page rather than one
    input, and dropping them here would quietly shrink the number of alerts ZAP
    is credited with.
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
    """Everything else ZAP said.

    Counted and reported rather than thrown away. ZAP looks for roughly a
    hundred classes and ProofScan looks for two, and a comparison that hides
    that is dishonest in ProofScan's favour.
    """
    return [a for a in alerts if a.kind is None]
