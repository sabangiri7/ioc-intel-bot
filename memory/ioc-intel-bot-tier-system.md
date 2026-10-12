---
name: ioc-intel-bot-tier-system
description: Three-tier evidence model for ioc-intel-bot sources
type: project
---

## Evidence tiers

| Tier | Sources | Confidence | Importable |
|---|---|---|---|
| **A** | ThreatFox, URLhaus, Feodo, MalwareBazaar, CISA KEV (5) | 3 pts | Yes |
| **B** | 15 RSS/CERT/news feeds | 2 pts (explicit), 1 pt (incidental) | With qualification |
| **C** | 6 blocklists (ET Compromised, IPsum, DShield, etc.) | 0 pts | No (context only) |
| **MITRE** | Enrichment only (family/actor → technique IDs) | — | No |

## Confidence rules
- +1 point if ≥ 2 distinct publishers corroborate
- Thresholds: CRITICAL ≥6, HIGH ≥3, MEDIUM ≥2, LOW <2
- Staleness: MEDIUM/HIGH older than 180d → MEDIUM; older than 365d → LOW

## Source registry (sources.yaml)
- `kind`: maps to COLLECTORS registry (threatfox, urlhaus, feodo, malwarebazaar, cisa_kev, ip_list, domain_list, url_list, report)
- `tier`: A, B, or C
- `enabled`: boolean
- `max_articles`: per-feed cap (Tier B only)
- `max_age_days`: feed freshness window (default 21)
- `max_entries`: max list entries (blocklists)

## Malware family classification
- `classify.py`: FAMILY_CATEGORY maps family name → category
- Family noise filter: NOISE_TAGS / FAMILY_TAG_NOISE prevent noise from being treated as families
- Article category patterns: per-sentence classification using ARTICLE_CATEGORY_PATTERNS
