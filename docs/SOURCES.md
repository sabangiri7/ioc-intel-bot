# Data sources

28 configured sources: **27** across three evidence tiers (5 Tier-A, 15 Tier-B,
7 Tier-C) plus MITRE ATT&CK enrichment, which is a mapping rather than a feed.
**26 of the 27 tiered sources are enabled** — Emerging Threats Block IPs is
`enabled: false`. Edit `config/sources.yaml` to change this list — see
[CONFIGURATION.md](CONFIGURATION.md) for the schema.

## What the tiers mean

| Tier | Evidence | Confidence contribution |
|---|---|---|
| **A** | Curated structured malware/C2 feeds (the publisher's curation *is* the evidence) | 3 points per source |
| **B** | Vendor/CERT/news reports (evidence is the article *text*) | 2 points if the sentence explicitly calls it malicious/C2, else 1 |
| **C** | Aggregated blocklists — context only | 0 points; capped LOW, never importable alone |

An extra **+1 confidence point** is added when ≥ 2 distinct publishers are seen.

---

## Tier A — structured feeds (5 / 5 enabled)

Machine-readable, high-confidence. No per-cycle article cap.

| Name | URL | Notes |
|---|---|---|
| ThreatFox (abuse.ch) | `https://threatfox.abuse.ch/export/json/recent/` | On an **empty database** (first run) it pulls the **full** dump via `first_run_url` instead of `recent` — much larger, slower first cycle. |
| URLhaus (abuse.ch) | `https://urlhaus.abuse.ch/downloads/csv_online/` | Malware distribution URLs. |
| Feodo Tracker (abuse.ch) | `ip_url: .../downloads/ipblocklist.txt` | Botnet C2 IPs. Uses `ip_url`/`browse_url`, **not** `url`. |
| MalwareBazaar (abuse.ch) | `https://bazaar.abuse.ch/export/csv/recent/` | Malware samples → MD5/SHA256. |
| CISA KEV | `known_exploited_vulnerabilities.json` | Emits CVEs tagged `cisa-kev` / `known-exploited`; `ransomware-use` when known ransomware use is recorded. |

---

## Tier B — report feeds (15 / 15 enabled)

RSS/Atom vendor, CERT, and security-news feeds. Articles are **relevance-gated
before the body is fetched** (title+summary must match `RELEVANCE_RE` in
`classify.py`), then age-filtered (`max_age_days`) and capped (`max_articles`).
IOC categories and explicit-malicious flags are decided **per sentence**, not per
article. Sentences marking "legitimate …" infrastructure get tagged
`legit-service-abused` (master-only, severity capped MEDIUM).

| Name | `max_articles` | `max_age_days` |
|---|---|---|
| CISA Advisories | 8 | 30 |
| Cisco Talos | 8 | 21 |
| Palo Alto Unit 42 | 8 | 21 |
| Malwarebytes Research | 8 | 21 |
| ESET WeLiveSecurity | 8 | 21 |
| Kaspersky Securelist | 8 | 30 |
| Check Point Research | 8 | 30 |
| Microsoft Security Blog | 6 | 21 |
| CrowdStrike Blog | 6 | 21 |
| The Hacker News | 10 | 14 |
| BleepingComputer | 10 | 14 |
| KrebsOnSecurity | 6 | 21 |
| Help Net Security | 6 | 14 |
| GBHackers | 6 | 14 |
| HackRead | 6 | 14 |

Vendor/CERT sources use a 21–30 day window; the general news outlets use a
tighter 14-day window.

---

## Tier C — blocklists (7 configured / 6 enabled)

Context-only aggregates. Every mention is tagged `blocklist` + `context-only`,
`categories=[OTHER]` (`[PHISHING]` if the source name contains "phish"), and is
capped to LOW confidence — a blocklist hit alone never reaches
`CROWDSTRIKE_IOC_IMPORT.csv`. Useful for corroborating a Tier-A/B indicator.

| Name | Type | `max_entries` | Enabled |
|---|---|---|---|
| Emerging Threats Compromised IPs | ip | — | yes |
| Emerging Threats Block IPs | ip | — | **no** |
| CI Army Bad Guys | ip | 5000 | yes |
| IPsum (DShield aggregates) | ip | 5000 | yes |
| DShield Block List | ip | — | yes |
| ISC Suspicious Domains | domain | — | yes |
| OpenPhish | url | — | yes |

---

## MITRE ATT&CK enrichment

Not a source of IOCs — it adds context. The Enterprise ATT&CK STIX bundle maps a
malware family or threat actor to its technique IDs (capped at ~8 techniques per
entity). Cached to `data/cache/enterprise-attack.json`, refreshed every
`refresh_days` (30). Disabled with `mitre.enabled: false` in `sources.yaml`.

---

## Adding a source

1. Add an entry to the right tier list in `config/sources.yaml`.
2. Set `kind` to a value in the `COLLECTORS` registry (`iocbot/collectors/__init__.py`):
   `threatfox`, `urlhaus`, `feodo`, `malwarebazaar`, `cisa_kev` (Tier A);
   `ip_list`, `domain_list`, `url_list` (Tier C). Tier-B report feeds are
   selected automatically by being under `reports:`.
3. Tier-B sources: give `max_articles` and `max_age_days`. They are relevance-gated
   by the shared regex — there is no per-source keyword list.
4. Run `python3 -m iocbot.cli --sources <name> --json` to test just that source.

New collector *kinds* require a function in `collectors/` returning `Mention`
objects and an entry in the `COLLECTORS` registry — see
[ARCHITECTURE.md](ARCHITECTURE.md).