# IOC Intel Bot — Codebase Overview

**Project:** IOC Intel Collection Bot
**Purpose:** Collect, validate, normalize, deduplicate, score, and export threat-indicator IOCs focused on C2 infrastructure, malware distribution, and cracked/pirated/fake-software malware.
**Audience:** Manual security analysts. This is a **preparation** tool, not an automated defense system.

---

## Quick navigation

| Concern | Where to look |
|---|---|
| "How does the bot work end-to-end?" | `CLAUDE.md` (this file's sibling) — data flow diagram |
| "What does each module do?" | `docs/ARCHITECTURE.md` — module map + storage schema |
| "How do I configure sources?" | `config/sources.yaml` + `docs/CONFIGURATION.md` |
| "How do I run the bot?" | `docs/OPERATIONS.md` — CLI flags, server startup, troubleshooting |
| "What API endpoints exist?" | `docs/API.md` — endpoint reference + auth model |
| "What sources are configured?" | `docs/SOURCES.md` — per-source table |
| "How is the frontend structured?" | `iocbot/web/README.md` + `iocbot/web/src/` |

---

## Repository layout

```
ioc-intel-bot/
├── iocbot/                    # Main Python package
│   ├── __init__.py            # Package docstring (safety guarantees)
│   ├── cli.py                 # argparse entry point
│   ├── pipeline.py            # Collection orchestrator (the core)
│   ├── models.py              # Mention/Extraction dataclasses, IOC types, categories
│   ├── store.py               # SQLite layer: schema, WAL, FTS5, migrations, upsert
│   ├── query.py               # Read-side: Database class, search_iocs() with views
│   ├── validate.py            # False-positive gates (Validator class)
│   ├── normalize.py           # Canonicalization per IOC type
│   ├── score.py               # Confidence/severity computation + CS import flag
│   ├── classify.py            # Family→category mapping; relevance regexes
│   ├── extract.py             # Regex IOC extraction + refang()
│   ├── export.py              # CSV/STIX export writer
│   ├── summary.py             # IOC_SUMMARY.txt renderer
│   ├── folders.py             # Auto + manual folder CRUD
│   ├── http.py                # Polite HTTP Fetcher (rate limiting, cache)
│   ├── mitre.py               # MITRE ATT&CK STIX index for enrichment
│   ├── keys.py                # API key generation, PBKDF2 passwords, roles/scopes
│   ├── push.py                # Outbound SIEM push (Splunk HEC, ES, webhook)
│   ├── api/
│   │   ├── __init__.py
│   │   └── server.py          # FastAPI app: /api/v1/* + dashboard mount
│   └── web/                   # React+TypeScript dashboard (Vite build → dist/)
│       ├── package.json
│       ├── src/
│       │   ├── pages/         # ApiPage, Kitchen, Login, Drawer, IocTable
│       │   ├── components/ui/ # Badge, Button, Checkbox, Chip, Input, Popover, ...
│       │   ├── lib/           # api.ts, ui.tsx, utils.ts
│       │   └── App.tsx
│       └── dist/              # Built frontend (served by FastAPI)
├── config/                    # YAML configuration (none contain live secrets)
│   ├── sources.yaml           # Feeds, blocklists, reports, MITRE config
│   ├── validation.yaml        # False-positive rejection/flag rules
│   ├── crowdstrike.yaml       # Export shape & thresholds (no API calls)
│   ├── push.yaml              # SIEM push targets (off by default)
│   └── api.yaml               # Server bind address, auth settings
├── data/                      # [GITIGNORED] Runtime state
│   ├── state.db               # SQLite master database
│   ├── cache/                 # Raw feed downloads + MITRE bundle
│   ├── keys/                  # Bootstrap admin key
│   └── logs/                  # iocbot.log, cron.log
├── output/                    # [GITIGNORED] Generated exports
│   └── daily/<date>/          # Per-cycle CSV artifacts + IOC_SUMMARY.txt
├── tests/                     # pytest suite
├── docs/                      # Reference documentation
│   ├── ARCHITECTURE.md
│   ├── CONFIGURATION.md
│   ├── OPERATIONS.md
│   ├── API.md
│   └── SOURCES.md
├── .githooks/                 # Pre-commit secret scanner
├── .github/workflows/         # GitHub Actions (cron collection)
├── requirements.txt
└── README.md
```

---

## Architecture in one paragraph

`Pipeline.run()` in `iocbot/pipeline.py` is the heart of the system. It loads YAML config, iterates over configured sources (feeds, blocklists, reports) via the `COLLECTORS` registry, collects raw `Mention[]` objects, validates each mention against rules in `validation.yaml`, normalizes values, upserts them into a SQLite database (`data/state.db`), scores confidence/severity, enriches with MITRE ATT&CK technique IDs, then exports dated CSV artifacts and writes a summary. The FastAPI server in `api/server.py` reads from the same database and serves both a REST API (`/api/v1/*`) and a React dashboard. All four output paths (CSV export, API, SIEM push, summary) read the same scored rows, ensuring consistency.

---

## Key design decisions

1. **SQLite as single source of truth.** Everything — the API, exports, push, dashboard — reads from `data/state.db`. No secondary caches.
2. **Upsert-by-merge.** `(ioc_type, ioc)` is the primary key. Repeated observations union categories/tags/sources; `first_seen` keeps earliest, `last_seen` keeps latest.
3. **Three-tier evidence model.** Tier A (structured feeds) → high confidence; Tier B (reports) → medium, relevance-gated; Tier C (blocklists) → low, context-only.
4. **Validation gates, not hard blocks.** `SHARED-PLATFORM` and `REJECTED` outcomes still land in the DB for analyst review; only `VALID` rows become exportable.
5. **Materialized category views.** `flag_c2` and `flag_malware` are integer columns on `iocs`, backfilled once, so dashboard views are cheap index scans.
6. **No external API calls for response.** CrowdStrike config describes export shape only; there is no Falcon API client in the codebase.
7. **Security-by-design.** Pre-commit secret scanner, PBKDF2-hashed passwords, scoped API keys, gitignored runtime state.

---

## Updating a collector

1. Add or modify the function in `iocbot/collectors/<source>.py`.
2. Register it in `iocbot/collectors/__init__.py` under `COLLECTORS`.
3. Add a config entry in `config/sources.yaml` under `feeds:`, `blocklists:`, or `reports:`.
4. Add tests in `tests/test_<module>.py`.
5. Update `docs/SOURCES.md` if the source is publicly documented.

---

## Adding a new IOC type

1. Append to `IOC_TYPES` in `iocbot/models.py`.
2. Add validation logic in `iocbot/validate.py`.
3. Add normalization in `iocbot/normalize.py`.
4. Add extraction regex in `iocbot/extract.py`.
5. Update `DAILY_IOC_TYPES` in `iocbot/export.py` if it should appear in daily exports.
6. Update `CS_EXPORT_COLUMNS` / `CS_SUPPORTED_TYPES` if CrowdStrike-compatible.
7. Add tests.

---

## Running tests

```bash
pytest tests/ -v
pytest tests/test_pipeline.py -v    # target a specific module
```

Tests stub collectors and the fetcher — no network access required.

---

## Common modifications

- **Change collection schedule:** Edit `.github/workflows/iocbot.yml` (cron expression).
- **Add a new feed:** Edit `config/sources.yaml`, add collector code, register in `__init__.py`.
- **Tighten validation:** Edit `config/validation.yaml` (no code change needed for most gates).
- **Change scoring thresholds:** Edit `config/crowdstrike.yaml` (confidence/severity thresholds).
- **Enable SIEM push:** Edit `config/push.yaml`, add targets.
- **Rebuild dashboard:** `cd iocbot/web && npm run build`.
- **Reset state:** Delete `data/state.db` and re-run; first run pulls ThreatFox full dump.
