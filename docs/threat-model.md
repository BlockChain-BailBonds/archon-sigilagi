# Threat model

Untrusted public content is data only. Fetchers hash and size-limit bytes, use isolated egress, and never execute retrieved content. Extractors have no credentials. Planners emit only schema-valid plans referencing registry primitives. OPA policy is signed and independently versioned; no model identity can change policy and deploy under it. Deployment and telemetry identities are separate. Audit events are append-only and hash chained.

The primary residual risks are incorrect applicability, compromised adapters, telemetry blind spots, and malicious or stale authoritative feeds. Mitigations are two-source evidence, reachability checks, 95% telemetry coverage, bounded expiry, canaries, and automatic rollback.

