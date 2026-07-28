"""CycloneDX and SPDX JSON ingestion into the common asset contract."""
import json
from .models import Asset, now

def assets_from_sbom(payload: dict, *, environment: str, service: str, asset_prefix: str = "sbom") -> list[Asset]:
    result = []
    if payload.get("bomFormat") == "CycloneDX":
        components = payload.get("components", [])
        for i, component in enumerate(components):
            result.append(Asset(f"{asset_prefix}-{i}", "software", service, component.get("name", "unknown"), component.get("version", "unknown"), environment, False))
    elif payload.get("spdxVersion"):
        for i, package in enumerate(payload.get("packages", [])):
            result.append(Asset(f"{asset_prefix}-{i}", "software", service, package.get("name", "unknown"), package.get("versionInfo", "unknown"), environment, False))
    else:
        raise ValueError("unsupported SBOM: expected CycloneDX or SPDX JSON")
    return result

