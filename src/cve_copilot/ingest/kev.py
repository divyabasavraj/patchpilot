"""Parse the CISA Known Exploited Vulnerabilities feed."""
from .models import KevEntry


def parse_kev(data: dict) -> list[KevEntry]:
    vulns = data.get("vulnerabilities") if isinstance(data, dict) else None
    if not isinstance(vulns, list):
        raise ValueError("KEV data has no 'vulnerabilities' list")
    return [
        KevEntry(v["cveID"], v.get("dateAdded", ""), v.get("knownRansomwareCampaignUse", ""))
        for v in vulns
        if v.get("cveID")
    ]
