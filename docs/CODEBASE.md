# ioc-intel-bot Codebase Reference

Complete technical reference for the codebase, organized by concern.

## Directory structure

```
ioc-intel-bot/
├── CLAUDE.md              ← agent context (auto-loaded by Claude)
├── README.md              ← human-facing project overview + run instructions
├── config/                ← YAML configuration files (4 files, see below)
├── data/                  ← runtime state — never commit (gitignored)
│   ├── state.db           ← SQLite database (WAL mode, full-text search)
│   ├── cache/raw/         ← raw HTTP cache (by URL SHA256 hash, 7-day TTL)
│   ├── keys/              ← API key files (SHA-256 hashes on disk)
│   └── logs/
├── iocbot/                ← Python package (core logic)
│   ├── __init__.py
│   ├── cli.py             ← CLI entry point (argparse, config checks)
│   ├── pipeline.py        ← main orchestration (collect → validate → store → score → export)
│   ├── store.py           ← SQLite schema, WAL pragmas, FTS5, upsert logic
│   ├── query.py           ← read-side Database class + search_iocs() filters
│   ├── models.py          ← IOC types, Mention/Extraction dataclasses, categories
│   ├── validate.py        ← Validator: every validation.yaml gate
│   ├── normalize.py       ← canonicalize IOC values per type
│   ├── score.py           ← confidence + severity computation
│   ├── export.py          ← CSV artifact writer (6 artifact types)
│   ├── summary.py         ← IOC_SUMMARY.txt writer
│   ├── push.py            ← outbound SIEM delivery (Splunk HEC, Elasticsearch, webhook)
│   ├── folders.py         ← folder CRUD, sync_auto_folders()
│   ├── keys.py            ← API key + user auth (PBKDF2, roles, scopes)
│   ├── http.py            ← polite Fetcher (rate limiting, retries, disk cache)
│   ├── extract.py         ← regex IOC extraction + refang()
│   ├── classify.py        ← family→category taxonomy, regex gates
│   ├── mitre.py           ← MITRE ATT&CK STIX index (enrichment)
│   ├── api/               ← FastAPI server
│   │   └── server.py      ← full API + dashboard mount
│   ├── collectors/        ← source-specific collectors
│   │   ├── __init__.py    ← COLLECTORS registry
│   │   ├── abusech.py     ← ThreatFox, URLhaus, Feodo, MalwareBazaar
│   │   ├── reports.py     ← RSS/Atom report ingestion (Tier B)
│   │   └── blocklists.py  ← IP/domain/URL blocklist parsers (Tier C)
│   └── web/               ← React/TypeScript dashboard
│       ├── package.json
│       ├── vite.config.ts ← base: '/static/', proxy '/api' → 127.0.0.1:8080
│       ├── src/
│       │   ├── pages/     ← ApiPage, Kitchen, Login, Drawer, IocTable
│       │   └── components/← ui/ (Badge, Button, Chip, Input, Popover, etc.)
├── config/
│   ├── api.yaml           ← server host/port, auth settings, bootstrap key
│   ├── sources.yaml       ← 27 feed definitions across 3 tiers + MITRE
│   ├── validation.yaml    ← false-positive gates (domains, TLDs, IPs, hashes, CVEs)
│   ├── crowdsrike.yaml    ← export shape (type lists, thresholds)
│   └── push.yaml          ← outbound SIEM targets (disabled by default)
├── tests/                 ← pytest test suite (13 files)
├── docs/                  ← detailed reference docs (API.md, ARCHITECTURE.md, etc.)
└── .githooks/             ← pre-commit secret scanner
```

## Module dependency graph (top-level)

```
cli.py
  └── pipeline.py
        ├── collectors/* (abusech, reports, blocklists)
        ├── validate.Validator
        ├── normalize.norm_value
        ├── store.Store
        ├── score.score_row
        ├── export.write_all
        └── summary.write_summary

api/server.py
  ├── query.Database (read-side)
  ├── folders.sync_auto_folders
  ├── keys (auth: verify_key, create_session, etc.)
  └── push.push_now (triggered via POST /api/v1/push)

push.py
  └── query.Database (read-side, with filters)

http.py (Fetcher)
  └── used by: collectors, mitre, push

mitre.py (MitreIndex)
  └── enriches pipeline: family/actor → technique IDs

classify.py / extract.py
  └── used by: reports.py collector
```

## Collector registry

`collectors/__init__.py` maps `kind` → function:

| kind | collector | tier | source |
|---|---|---|---|
| `threatfox` | collect_threatfox | A | threatfox.abuse.ch/export/json/recent/ |
| `urlhaus` | collect_urlhaus | A | urlhaus.abuse.ch/downloads/csv_online/ |
| `feodo` | collect_feodo | A | feodotracker.abuse.ch (two URLs) |
| `malwarebazaar` | collect_malwarebazaar | A | bazaar.abuse.ch/export/csv/recent/ |
| `cisa_kev` | collect_cisa_kev | A | known_exploited_vulnerabilities.json |
| `ip_list` | collect_ip_list | C | various blocklist URLs |
| `domain_list` | collect_domain_list | C | various blocklist URLs |
| `url_list` | collect_url_list | C | various blocklist URLs |
| `report` | collect_reports | B | RSS/Atom feeds (21–30 day window) |

## SQLite schema (state.db)

```sql
-- Core IOC table (PK: ioc_type, ioc)
CREATE TABLE iocs (ioc, ioc_type, threat, malware_family, threat_actor, campaign,
  category, confidence, severity, first_seen, last_seen, source, source_url,
  description, tags, mitre_attack, crowdstrike_supported, crowdstrike_importable,
  validation_status, sources_detail, evidence, first_cycle, last_cycle,
  updated_at, flag_c2, flag_malware);

-- Category index for filtering
CREATE TABLE ioc_categories (ioc_type, ioc, category);

-- FTS5 for text search
CREATE VIRTUAL TABLE iocs_fts USING fts5(ioc, malware_family, threat_actor, description, tags);

-- Cycle history
CREATE TABLE cycles (id INTEGER PRIMARY KEY, started, finished, stats);

-- Manual + auto folders
CREATE TABLE folders (id, name, kind, field, value, description, color, created_at);
CREATE TABLE folder_iocs (folder_id, ioc_type, ioc);

-- API keys + dashboard users
CREATE TABLE api_keys (id, name, prefix, key_hash, scopes, platform, created_at,
  last_used_at, uses, last_ip, revoked);
CREATE TABLE users (id, username, password_hash, full_name, role, disabled, created_at, last_login_at);

-- Push history
CREATE TABLE push_log (id, target, status, sent, detail, pushed_at);

-- Sentinels for one-time migrations
CREATE TABLE meta (key PRIMARY KEY, value);
```

## Data flow (detailed)

### Normal flow
1. **Pipeline.run()** starts cycle (store.begin_cycle)
2. **Load MITRE** (if enabled, cached 30-day TTL)
3. **For each source in sources.yaml:**
   - Call collector → returns list[Mention]
   - **Validate**: Validator.validate() per mention → VALID / SHARED-PLATFORM / REJECTED
   - **Normalize**: norm_value() canonicalizes (domain lower, URL port/fragment, hash lower)
   - **Store.upsert()**: merge on (ioc_type, ioc); union categories/tags/sources; keep earliest first_seen
   - **Derive host IOCs**: URL hosts → IPv4/IPv6/Domain (only from Tier A/B)
4. **Score all touched rows**: confidence points per tier, +1 for multi-publisher, staleness decay
5. **Flush to SQLite**: upsert-merge per row; rebuild ioc_categories, FTS5 triggers
6. **Sync folders**: create auto folders for every malware_family/threat_actor
7. **Export**: write 6 CSV artifacts + folder CSVs + index
8. **Write summary**: IOC_SUMMARY.txt with stats, sources, reject breakdown

### Per-cycle stats tracked
- `cycle_id`, `duration_seconds`, `first_run`
- Per-source: fetched, entries, mentions, articles, errors
- Processing: accepted, rejected, reject_reasons breakdown
- Rows scored, written
- Export counts per artifact
- Distribution by severity/confidence/validation_status/importability

## Scoring model (score.py)

**Confidence** points per source:
- Tier A: 3 pts
- Tier B explicit (explicit_c2/explicit_malware): 2 pts, else 1 pt
- Tier C: 0 pts
- +1 if ≥ 2 publishers
- Thresholds: CRITICAL ≥ 6, HIGH ≥ 3, MEDIUM ≥ 2, LOW < 2
- Staleness: MEDIUM/HIGH > 180d → MEDIUM; > 365d → LOW
- Tier-C-only → forced LOW

**Severity** evaluated in order:
1. CVE → HIGH (bumped to HIGH if Tier-A or multi-publisher)
2. C2 → CRITICAL if active or ≤30d; HIGH (31–180d); MEDIUM (>180d); LOW (>365d)
3. RANSOMWARE with Tier-A → HIGH; any explicit-malware/C2 → HIGH
4. Otherwise tracks confidence: MEDIUM→MEDIUM, else LOW
5. Tier-C-only → LOW/LOW
6. blocked tags (`shared-platform`, `legit-service-abused`, `generic-vendor`, `cdn`) → severity cap MEDIUM

**Import gate**: supported type + VALID + confidence/threat Medium+ + none of the blocked tags.

## Validation gates (validate.py)

Gates checked per IOC type (domain, IP, hash, URL, email, file, CVE):
- Syntax: correct format (IP, hash length, CVE year, file name pattern, etc.)
- Reserved: private/reserved IPs, placeholder hashes (repetitive chars)
- TLD: unknown, reserved (`.onion`, `.i2p`), documentation domains
- Shared infrastructure: shared-platform domains, CDN suffixes
- Generic vendor: known-generic-vendor domains
- URL scheme: http/https/ftp only
- CVE year: 1999–current

## Key API endpoints

### Public (unauthenticated)
- `GET /api/v1/health` — `{status, iocs, version}`
- `GET /api/v1/auth/status` — `{auth_required, has_users, allow_registration, bootstrap_available}`

### Authenticated (X-API-Key / Authorization: Bearer / ?apikey=)
- `GET /api/v1/auth/me` — current user info
- `GET /api/v1/iocs?...` — search/filter (severity, confidence, type, category, view, folder, etc.)
- `GET /api/v1/feed?format=csv` — full feed
- `GET /api/v1/folders` — list folders
- `GET /api/v1/stats` — counts by severity/confidence/type/validation
- `POST /api/v1/auth/login` — username/password → session key
- `POST /api/v1/auth/provision` — first user setup (requires bootstrap key)
- `POST /api/v1/auth/bootstrap` — claim admin key (first run only)
- `POST /api/v1/auth/register` — self-service registration (viewer/analyst only)

### Admin only
- `GET/POST /api/v1/users` — list + create users
- `PUT /api/v1/users/{id}/role` — change role
- `PUT /api/v1/users/{id}/disabled` — enable/disable
- `GET/POST /api/v1/keys` — list + create API keys
- `DELETE /api/v1/keys/{id}` — revoke key
- `POST /api/v1/keys/{id}/rotate` — rotate key
- `POST /api/v1/folders` — create folder
- `PUT /api/v1/folders/{id}` — update folder
- `DELETE /api/v1/folders/{id}` — delete folder
- `POST /api/v1/folders/{id}/sync` — sync auto folders

### Admin + write
- `POST /api/v1/iocs` — create IOC
- `PUT /api/v1/iocs/{type}/{ioc}` — update IOC
- `DELETE /api/v1/iocs/{type}/{ioc}` — delete IOC
- `POST /api/v1/folders/{id}/iocs` — add IOCs to folder
- `DELETE /api/v1/folders/{id}/iocs/{type}/{ioc}` — remove from folder
- `POST /api/v1/push` — trigger outbound push

### Run control
- `GET /api/v1/run` — collection run status
- `POST /api/v1/run` — trigger collection (requires write)
- `GET /api/v1/push` — push configuration + log

## Web dashboard

Served from FastAPI at `/` (production build from `web/dist/`). Login page first run:
1. Checks auth_required + has_users + bootstrap_available
2. If bootstrap key exists and no users: provisioning flow available
3. Self-service registration for viewer/analyst roles

After login: command-center layout with:
- KPI strip (total IOCs, severity breakdown, new today, importable, C2, malware)
- Sidebar views: All / Recently Added / Critical / SIEM-Importable / Needs Review / C2 / Malware
- Searchable Threat Folder browser
- Sortable intelligence table with bulk actions
- API & Integrations page

## Running modes

### Development (human)
```bash
# Backend
python3 -m iocbot.cli --no-auth --verbose --max-articles 3

# API + dashboard
python3 -m iocbot.api.server --no-auth --host 127.0.0.1 --port 8080

# Dev server + Vite proxy
python3 -m iocbot.api.server --host 127.0.0.1 --port 8080
cd iocbot/web && npm run dev   # → http://localhost:5173
```

### CI/CD (stateless)
GitHub Actions at `.github/workflows/iocbot.yml` runs at 12:00 & 16:00 UTC.
Each run collects and uploads `output/`, logs, and `state.db` as a 7-day artifact.
No cross-run NEW_IOCS history (stateless).

### Scheduling
- cron: `0 12,16 * * * cd /path/to/ioc-intel-bot && python3 -m iocbot.cli >> data/logs/cron.log 2>&1`
- systemd user timer: units in `deploy/iocbot.{service,timer}`

## Test coverage

```bash
pytest tests/ -v
```

13 test files covering:
- `test_abusech_helpers.py` — collector helpers (family extraction, tag splitting, refang)
- `test_api_folders_export.py` — API folder endpoints + folder CSV export
- `test_blocklists.py` — IP/domain/URL blocklist parsers
- `test_cli.py` — CLI argument parsing, config checks, stats output
- `test_extract_normalize.py` — regex extraction + refang + normalization
- `test_http.py` — Fetcher rate limiting, caching, retries
- `test_pipeline.py` — orchestration: mock collectors, validation, scoring, export
- `test_push.py` — outbound push (Splunk HEC, Elasticsearch)
- `test_reports.py` — RSS article parsing, relevance gating, sentence classification
- `test_roles.py` — API key auth, role management, session handling
- `test_score.py` — confidence + severity scoring, import gate
- `test_store_export.py` — SQLite schema, upsert, FTS5, export CSV generation
- `test_validate.py` — every validation gate (domain, IP, hash, URL, email, CVE, file)
