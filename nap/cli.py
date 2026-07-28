import argparse, json
from .models import *
from .engine import propose
from .api import serve
from .kubernetes import inventory
from .storage import Store
from .sbom import assets_from_sbom
from .threat_feeds import cisa_kev, nvd_cve
from .guardian import watch
from .world_guard import watch_public, scan_public_threats

def main():
    p = argparse.ArgumentParser(prog="nap"); sub = p.add_subparsers(dest="command", required=True)
    demo = sub.add_parser("demo"); demo.add_argument("--json", action="store_true")
    server = sub.add_parser("serve"); server.add_argument("--host", default=None); server.add_argument("--port", type=int, default=None); server.add_argument("--db", default=None)
    k8s = sub.add_parser("inventory-kubernetes"); k8s.add_argument("--namespace"); k8s.add_argument("--db", default="nap.db")
    sbom = sub.add_parser("import-sbom"); sbom.add_argument("path"); sbom.add_argument("--environment", default="staging"); sbom.add_argument("--service", required=True); sbom.add_argument("--db", default="nap.db")
    cisa = sub.add_parser("ingest-cisa-kev"); cisa.add_argument("--url", default=None); cisa.add_argument("--db", default="nap.db")
    nvd = sub.add_parser("fetch-nvd"); nvd.add_argument("cve_id")
    guardian = sub.add_parser("watch"); guardian.add_argument("--interval", type=int, default=900); guardian.add_argument("--db", default="nap.db"); guardian.add_argument("--kubectl", default="kubectl"); guardian.add_argument("--cisa-url", default=None)
    world = sub.add_parser("global-watch"); world.add_argument("--interval", type=int, default=900); world.add_argument("--db", default="nap.db"); world.add_argument("--cisa-url", default=None)
    global_scan = sub.add_parser("global-scan"); global_scan.add_argument("--db", default="nap.db"); global_scan.add_argument("--cisa-url", default=None); global_scan.add_argument("--output", default=None)
    args = p.parse_args()
    if args.command == "serve":
        serve(args.host, args.port, args.db); return
    if args.command == "inventory-kubernetes":
        store=Store(args.db)
        assets=inventory(namespace=args.namespace)
        for asset in assets: store.put_asset(asset.asset_id, asset.__dict__, now())
        print(json.dumps({"stored":len(assets), "assets":[a.__dict__ for a in assets]}, indent=2)); return
    if args.command == "ingest-cisa-kev":
        claims, evidence, artifact = cisa_kev(args.url) if args.url else cisa_kev()
        store=Store(args.db); store.put_artifact(artifact.sha256, artifact.url, artifact.content_type, len(artifact.body), now(), artifact.body)
        for claim in claims: store.put_claim(claim.claim_id, artifact.sha256, {"schema_version":claim.schema_version,"claim_id":claim.claim_id,"observed_at":claim.observed_at,"source":claim.source.__dict__,"assertions":[a.__dict__ for a in claim.assertions],"indicators":claim.indicators,"extraction":{"executed_content":claim.executed_content}}, claim.observed_at)
        print(json.dumps({"claims":len(claims), "evidence":len(evidence), "sample": claims[0].__dict__ if claims else None}, indent=2, default=lambda value: value.__dict__)); return
    if args.command == "fetch-nvd":
        print(json.dumps(nvd_cve(args.cve_id), indent=2)); return
    if args.command == "watch":
        watch(Store(args.db), interval_seconds=args.interval, kubectl=args.kubectl, cisa_url=args.cisa_url); return
    if args.command == "global-watch":
        watch_public(Store(args.db), interval_seconds=args.interval, cisa_url=args.cisa_url); return
    if args.command == "global-scan":
        store=Store(args.db); result=scan_public_threats(store, cisa_url=args.cisa_url)
        if args.output:
            with open(args.output, "w", encoding="utf-8") as handle: json.dump({"updated_at":now(), "alerts":store.list_global_alerts(2000)}, handle, indent=2)
        print(json.dumps(result, indent=2)); return
    if args.command == "import-sbom":
        with open(args.path, encoding="utf-8") as handle: payload=json.load(handle)
        store=Store(args.db); assets=assets_from_sbom(payload, environment=args.environment, service=args.service)
        for asset in assets: store.put_asset(asset.asset_id, asset.__dict__, now())
        print(json.dumps({"stored":len(assets), "assets":[a.__dict__ for a in assets]}, indent=2)); return
    if args.command == "demo":
        raw = b"vendor advisory: Example Gateway CVE-2026-00001"
        claim = ThreatClaim(Source("vendor_advisory", "demo://advisory", __import__('hashlib').sha256(raw).hexdigest()), [Assertion("Example Vendor", "Example Gateway", [">=4.1.0 <4.1.8"], ["CVE-2026-00001"], "network", "unauthenticated", ["service_disruption"])])
        evidence = [Evidence("vendor_advisory", "vendor", True, .96, "vendor-primary", claim.claim_id), Evidence("cisa_kev", "cisa_kev", True, .98, "cisa", claim.claim_id)]
        asset = Asset("asset-1", "kubernetes", "gateway-api", "Example Gateway", "4.1.6", "production", True, rollback_target="sha256:known-good")
        plan, score, decision = propose(claim, evidence, asset, "disable_feature_flag", {"feature":"legacy_parser", "enabled":False})
        out = {"claim": claim.claim_id, "score": score.__dict__, "plan": plan.__dict__, "decision": decision.__dict__}
        print(json.dumps(out, indent=2))

if __name__ == "__main__":
    main()
