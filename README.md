# Archon SigilAGI

Archon SigilAGI was inspired by the **Neural-Auto-Patch meme**: the idea of an AI guardian that sees emerging threats, plans a rescue, and protects systems. This implementation turns that meme into a policy-bounded defensive platform with real public threat ingestion, signed-by-commit intelligence refreshes, enrolled-tenant correlation, and reversible response boundaries.

A policy-bounded autonomous vulnerability-containment MVP. Models may extract claims and propose typed plans; deterministic policy and approved primitive adapters retain production authority.

## Run locally

```bash
cd /home/nine1eight/neural-auto-patch
python3 -m pytest -q
python3 -m nap.cli demo
```

Run the actual local control-plane API:

```bash
python3 -m nap.cli serve --db ./nap.db
curl http://127.0.0.1:8099/healthz
curl -X POST http://127.0.0.1:8099/api/v1/sboms \
  -H 'Content-Type: application/json' -H 'X-NAP-Service: gateway-api' \
  --data-binary @examples/sample.cyclonedx.json
curl http://127.0.0.1:8099/api/v1/assets
curl http://127.0.0.1:8099/api/v1/detections
```

Run the global public-threat sentinel:

```bash
python3 -m nap.cli global-watch --interval 900 --db ./global-threats.db
```

This continuously monitors the public CISA Known Exploited Vulnerabilities catalog and exposes worldwide alerts at `/api/v1/global/alerts`. GitHub Pages, Kaggle notebooks, and the API use the same committed canonical snapshot at `web/data/alerts.json`; the sentinel refreshes it every five minutes when GitHub Actions is available. It does not probe or modify unrelated systems.

Run the enrolled-tenant guardian loop against a Kubernetes context:

```bash
python3 -m nap.cli watch --interval 900 --db ./nap.db
```

Each cycle fetches the live CISA KEV catalog, inventories deployments, persists the raw feed and assets, correlates product names, and records a rescue plan plus deterministic decision for every match. A CISA-only match is intentionally escalated because exact version applicability and telemetry corroboration are not yet sufficient for autonomous quarantine. That is a real safety decision, not a simulated success.

The global sentinel is the world-facing layer. Autonomous rescue is only possible for enrolled organizations that provide asset inventory, telemetry, and an approved containment connector. No responsible system can alter arbitrary internet systems without their owners' authorization.

Import a real SBOM with `nap import-sbom`, or inventory a real Kubernetes cluster with `nap inventory-kubernetes` using the operator's configured `kubectl` context. The HTTP ingest client enforces HTTPS, DNS/IP checks, redirects-off, content-type allowlisting, streaming size limits, hashing, and no execution.

## MVP boundaries

Implemented functioning local components: durable SQLite storage, HTTP API, CycloneDX/SPDX import, explicit Kubernetes `kubectl` inventory, hardened HTTPS retrieval, deterministic evidence scoring, approved primitive registry, fail-closed policy, progressive canary with automatic rollback, and hash-chained audit events. Production deployment still requires wiring the organization’s PostgreSQL/object store, OPA, OTel, Cosign/TUF/in-toto, Argo, and cloud/network executor credentials; those must not be faked by a local demo.

Kernel, firmware, bootloader, trust-root, arbitrary shell, package installation, source rewriting, and irreversible data operations are intentionally outside autonomous scope.
