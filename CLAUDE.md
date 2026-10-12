# ioc-intel-bot — Agent Context

You are working on **IOC Intel Bot**, a Python threat-indicator collection tool that gathers C2, malware-distribution, and cracked-software IOCs from public sources, validates/scores/deduplicates them, and exports CSV for manual analyst review. It is a **research and preparation** tool only — it never blocks, responds, or calls any defense API.

## Tech stack
- **Backend:** Python 3.10+, SQLite (WAL mode), FastAPI + Uvicorn
- **Frontend:** Vite 8 + React 19 + TypeScript + Tailwind v4 + Radix UI + TanStack Table
- **Package manager:** pip (backend), npm (frontend)
- **Linting:** oxlint (frontend), ruff (implied by .gitignore)
- **Testing:** pytest
- **CI/CD:** GitHub Actions (cron at 12:00 & 16:00 UTC)

## Key directories

| Path | Contents |
|---|---|
| `iocbot/` | Core Python package |
| `iocbot/collectors/` | Source collectors (abuse.ch feeds, blocklists, RSS reports, CISA KEV) |
| `iocbot/api/` | FastAPI server + dashboard serving |
| `iocbot/web/` | React/TypeScript dashboard frontend (build to `dist/`) |
| `config/` | YAML config files (sources, validation, CrowdStrike export policy, push, API) |
| `data/` | **Runtime state only** — `state.db`, `cache/`, `keys/`, `logs/`. Never commit. |
| `output/daily/<date>/` | Dated CSV exports + `IOC_SUMMARY.txt` |
| `tests/` | pytest test suite |
| `docs/` | Architecture, configuration, operations, API, sources reference docs |
| `.githooks/` | Pre-commit secret scanner (`scan_history.py` for history audit) |
| `.github/workflows/` | GitHub Actions workflow |

## Entry points

```bash
python3 -m iocbot.cli              # Run one collection cycle
python3 -m iocbot.api.server       # Start API + dashboard (default 0.0.0.0:8080)
python3 -m iocbot.push             # Push IOCs to SIEM targets
python3 -m iocbot.keys             # CLI for API key management
```

## Data flow (single pipeline cycle)

```
sources.yaml ─┐
validation.yaml ─┤─> Pipeline.run()
crowdstrike.yaml ─┘     │
                        ├─ collectors/*  →  Mention[]
                        ├─ Validator     →  VALID / SHARED-PLATFORM / REJECTED
                        ├─ norm_value()  →  canonical IOC values
                        └─ Store.upsert →  data/state.db (SQLite)
                                       │
                                   score_row()
                                       │
                    ┌──────────────────┼──────────────────┬──────────────┐
               export.py           api/server.py       push.py      summary.py
            (CSV artifacts)      (FastAPI + web/)    (SIEM push)   (IOC_SUMMARY.txt)
```

## Tier system (evidence quality)

- **Tier A** — Curated structured feeds (ThreatFox, URLhaus, Feodo, MalwareBazaar, CISA KEV). High confidence, importable.
- **Tier B** — Vendor/CERT/news RSS reports. Relevance-gated by regex on article text. Medium confidence.
- **Tier C** — Aggregated blocklists. Tagged `context-only`, LOW confidence, never importable alone.
- **MITRE** — Enrichment only (malware/actor → ATT&CK technique IDs). Not a source tier.

## Core modules at a glance

| Module | Role |
|---|---|
| `pipeline.py` | Orchestrator: loads config, dispatches collectors, validate→normalize→store→score→export |
| `cli.py` | Argparse entry point; checks required configs exist |
| `store.py` | SQLite schema, WAL pragmas, FTS5 full-text search, migrations, `upsert()` merge logic |
| `query.py` | Read-side `Database` class + `search_iocs()` with filters and C2/malware/importable views |
| `models.py` | `Mention` / `Extraction` dataclasses; IOC types, column lists, category taxonomy |
| `validate.py` | `Validator` — every false-positive gate from `validation.yaml` |
| `normalize.py` | Canonicalizes IOC values per type (domain lowercasing, URL default-port stripping, etc.) |
| `score.py` | Computes `confidence` + `severity` from source tiers, explicit flags, active status |
| `classify.py` | Family→category mapping; relevance/malicious-sentence regex gates for report parsing |
| `extract.py` | Regex-based IOC extraction from article text + `refang()` (undoes `hxxp`, `[.]`, etc.) |
| `export.py` | Writes dated CSV artifacts to `output/daily/<date>/` |
| `summary.py` | Renders human-readable `IOC_SUMMARY.txt` |
| `folders.py` | Auto folders per family/actor + manual folder CRUD |
| `http.py` | Polite `Fetcher` — per-host rate limiting, retries, on-disk raw cache |
| `mitre.py` | MITRE ATT&CK STIX index for family/actor→technique enrichment |
| `keys.py` | API key generation, PBKDF2 password hashing, role/scope management |
| `push.py` | Outbound SIEM delivery (Splunk HEC, Elasticsearch, webhook) — off by default |
| `api/server.py` | FastAPI app: `/api/v1/*` endpoints, auth middleware, serves built dashboard |

## IOC types supported

`IPv4`, `IPv6`, `Domain`, `URL`, `SHA256`, `SHA1`, `MD5`, `Email`, `File-Name`, `File-Path`, `CVE`, `Malware`, `Threat-Actor`, `Campaign`

## Category taxonomy (key ones)

C2, MALWARE, MALWARE-DISTRIBUTION, CRACKED-SOFTWARE, PIRATED-SOFTWARE, FAKE-SOFTWARE, FAKE-UPDATE, INFOSTEALER, RAT, LOADER, BOTNET, RANSOMWARE, PHISHING, PAYLOAD-HOSTING, REDIRECTOR, APT, OTHER

## Validation outcomes

- **VALID** — passes all gates, exportable
- **SHARED-PLATFORM** — accepted but on shared/CDN infra; master DB only, not exported
- **REJECTED:<reason>** — failed a gate; reason codes: `syntax`, `private-or-reserved`, `localhost-or-literal`, `unknown-tld`, `reserved-tld`, `documentation-domain`, `generic-vendor`, `shared-infrastructure`, `placeholder-hash`, `scheme`, `bad-year`, `host-*`, `email-*`

## Export formats

- **Daily CSV** (`output/daily/<date>/`) — single-column IOC value lists per type
- **Master CSV** — all IOCs with full columns for manual review
- **CrowdStrike-importable CSV** — filtered by `crowdstrike_importable` flag (types: IPv4, IPv6, Domain, SHA256, MD5; VALID only; meets confidence/severity thresholds)
- **STIX 2.1 JSON** — machine-readable indicators
- **API** (`/api/v1/iocs`) — same data, filterable by severity, confidence, type, category, view (master/c2/malware/importable)

## Frontend

Located at `iocbot/web/`. Built with Vite → `dist/`. The FastAPI server mounts `dist/` at `/`. In development, run `npm run dev` in `iocbot/web/` for hot reload (Vite proxies `/api` to backend).

Pages: `ApiPage`, `Kitchen`, `Login`, `Drawer`, `IocTable`
UI primitives: `Badge`, `Button`, `Checkbox`, `Chip`, `Input`, `Popover`, `SegmentedControl`

## Safety guarantees

- **No response action** — never blocks, quarantines, or contains anything
- **No CrowdStrike API calls** — `crowdstrike.yaml` only describes export shape; `action: detect` is a column value, not a call
- **No DNS resolution or internal queries** — indicators are stored as text, never looked up
- **Public sources only** — configured feeds are open threat-intelligence sites
- **Pre-commit hook** scans for secrets before every commit (`.githooks/pre-commit`)

## Important paths to never commit

- `data/` — contains live `state.db` (hundreds of MB), API key hashes, user passwords
- `output/` — generated exports
- `config/*.local.yaml`, `config/secrets.yaml`, `.env` — runtime secrets
- `iocbot/web/node_modules/`, `iocbot/web/dist/` — build artifacts

## Tests

```bash
pytest tests/ -v
```

Focus areas: collector failure isolation, sources filter, skip flags, export output, scoring, validation, store persistence, API auth/folder/export.
