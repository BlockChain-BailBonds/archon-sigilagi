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

The container starts both the API and the continuous global CISA KEV sentinel. Set `ARCHON_SCAN_INTERVAL` to control the refresh interval in seconds.

For donations or compute sponsorship to operate the full always-on Hugging Face version, contact the founder: **founder918tech@gmail.com**.

Live dashboard: https://blockchain-bailbonds.github.io/archon-sigilagi/

Source and realtime canonical feed: https://github.com/BlockChain-BailBonds/archon-sigilagi
