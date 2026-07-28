"""Live CISA KEV, NVD, and RSS/vendor advisory adapters."""
from __future__ import annotations
import hashlib
import xml.etree.ElementTree as ET
from .models import Assertion, Evidence, Source, ThreatClaim
from .secure_ingest import fetch

CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

def cisa_kev(url: str = CISA_KEV_URL) -> tuple[list[ThreatClaim], list[Evidence], object]:
    artifact = fetch(url, max_bytes=50_000_000, allowed_types=("application/json",))
    payload = __import__("json").loads(artifact.body); claims=[]; evidence=[]
    for item in payload.get("vulnerabilities", []):
        cve=item.get("cveID"); vendor=item.get("vendorProject", "unknown"); product=item.get("product", "unknown")
        claim=ThreatClaim(Source("cisa_kev", url, artifact.sha256), [Assertion(vendor, product, ["unspecified"], [cve] if cve else [], "unknown", "unknown", ["active_exploitation"])])
        claims.append(claim); evidence.append(Evidence("cisa_kev", "cisa_kev", True, 1.0, "cisa-kev", claim.claim_id, artifact.sha256))
    return claims, evidence, artifact

def nvd_cve(cve_id: str, api_url: str = NVD_API_URL) -> dict:
    artifact = fetch(api_url + "?cveId=" + cve_id, max_bytes=10_000_000, allowed_types=("application/json",))
    return __import__("json").loads(artifact.body)

def vendor_rss(url: str) -> list[dict[str, str]]:
    artifact=fetch(url, allowed_types=("application/rss+xml", "application/xml", "text/xml")); root=ET.fromstring(artifact.body); entries=[]
    for item in root.findall(".//item"):
        entries.append({key: (item.findtext(key) or "").strip() for key in ("title", "link", "description", "pubDate")})
    return entries
