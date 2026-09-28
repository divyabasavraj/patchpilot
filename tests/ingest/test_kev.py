import pytest

from cve_copilot.ingest.kev import parse_kev
from cve_copilot.ingest.models import KevEntry


def test_parse_kev():
    data = {"vulnerabilities": [
        {"cveID": "CVE-2021-44228", "dateAdded": "2021-12-10",
         "knownRansomwareCampaignUse": "Known", "vendorProject": "Apache"},
        {"dateAdded": "2022-01-01"},    # no cveID: skipped
    ]}
    assert parse_kev(data) == [KevEntry("CVE-2021-44228", "2021-12-10", "Known")]


def test_wrong_shape_raises():
    with pytest.raises(ValueError):
        parse_kev({"title": "not a KEV file"})
