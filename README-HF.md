---
title: Archon SigilAGI
emoji: 🛡️
colorFrom: indigo
colorTo: purple
sdk: docker
app_port: 7860
---

# Archon SigilAGI

Global public-threat sentinel and policy-bounded containment control plane.

Configure an attached persistent volume at `/data`, then set `NAP_DB_PATH=/data/archon-sigilagi.db`. Set `NAP_INGEST_TOKEN` as a Space secret before accepting tenant SBOM uploads. The public read-only global alert endpoints do not require that token.
