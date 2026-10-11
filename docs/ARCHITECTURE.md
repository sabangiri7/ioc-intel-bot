# Architecture

How the IOC Intel bot is put together: the collection pipeline, the storage
model, the four output consumers, and what each module owns.

## Data flow

```
config/sources.yaml ─┐
config/validation.yaml ─┼─> Pipeline.run()  (iocbot/pipeline.py)
config/crowdstrike.yaml ┘        │
                                 ├─ collectors/*  ->  Mention[]
                                 ├─ Validator.validate()   [validation.yaml gates]
                                 ├─ norm_value()            [normalize.py]
                                 └─ Store.upsert()          [store.py -> data/state.db]
                                            │
                                        score_row()            [score.py]
                                            │
        ┌───────────────┬───────────────┬───┴─────────────┬──────────────┐
   export.py       api/server.py      push.py         summary.py
 (CSV artifacts)  (FastAPI + web/)  (Splunk/ES/hook)  (IOC_SUMMARY.txt)
```

One `Pipeline.run()` collects → validates → normalizes → stores → scores →
exports. The database (`data/state.db`) is the single source of truth; the CSV
files, the API, the dashboard, and outbound push are all *views* over it.

## Module map

### Collection

| Module | Responsibility |
|---|---|
| `pipeline.py` | Orchestrator. Loads config, builds `Validator`/`Fetcher`/`Store`, dispatches to collectors, derives host IOCs from malicious URLs (`derived-from-url`), then validate → normalize → store → score → export. |
| `cli.py` | `python3 -m iocbot.cli` entry point; argparse, config checks, logging. |
| `collectors/__init__.py` | `COLLECTORS` registry mapping a source's `kind` → collector function. |
| `collectors/abusech.py` | Tier-A: ThreatFox, URLhaus, Feodo, MalwareBazaar. Handles zipped payloads, tag-noise filtering, first-run full dump. |
| `collectors/advisories.py` | Tier-A: CISA KEV. Emits CVEs tagged `cisa-kev` / `known-exploited`. |
| `collectors/reports.py` | Tier-B: RSS/Atom. Relevance gate → age cutoff → article cap → BeautifulSoup body extraction → per-sentence classification. |
| `collectors/blocklists.py` | Tier-C: plain-list parsers (`ip_list` / `domain_list` / `url_list`); comment stripping, CIDR/malformed drop, `max_entries`. |
| `http.py` | Polite `Fetcher`: per-host rate limiting, size cap, retries, on-disk raw cache with stale-if-error fallback. |
| `extract.py` | Regex IOC extraction + `refang()` (undoes `hxxp`, `[:]`, `[.]`, `( )` defanging). |
| `classify.py` | Family→category taxonomy, the `RELEVANCE_RE` / `MALICIOUS_SENTENCE_RE` / `LEGIT_SENTENCE_RE` gates, category priority order. |
| `mitre.py` | MITRE ATT&CK STIX index — family/actor → technique IDs (enrichment, produces no IOCs). |

### Processing & storage

| Module | Responsibility |
|---|---|
| `validate.py` | The `Validator`: every `validation.yaml` gate. Returns `VALID` / `SHARED-PLATFORM` / `REJECTED:<reason>`. |
| `normalize.py` | Canonicalizes values per type before dedup (domain lower/`www.`/trailing-dot, URL default-port/fragment, CVE upper, etc.). |
| `score.py` | Confidence + severity computation and the CrowdStrike import flag. |
| `store.py` | SQLite schema, WAL pragmas, indexes, FTS5 triggers, migrations, `upsert()` merge. |
| `query.py` | Read side: `Database` + `search_iocs()` with filters and the C2/malware/importable views. |
| `models.py` | IOC types, column lists, orderings, the category taxonomy, `Mention`/`Extraction` dataclasses. |
| `folders.py` | Folder CRUD; `sync_auto_folders()` derives a folder per family/actor. |

### Delivery

| Module | Responsibility |
|---|---|
| `export.py` | Writes all CSV artifacts to `output/daily/<date>/`. |
| `summary.py` | Renders `IOC_SUMMARY.txt` (totals, per-source status, reject breakdown, distributions) + the safety notes. |
| `api/server.py` | FastAPI app: the `/api/v1` endpoints, auth, and the `web/` dashboard. |
| `keys.py` | API-key and dashboard-user auth primitives (key generation, hashing, PBKDF2 passwords, scopes, sessions). |
| `push.py` | Outbound SIEM push (Splunk HEC / Elasticsearch / webhook). |

`iocbot/web/` holds the dashboard front-end — a Vite + React + TypeScript app
(`src/`, built to `dist/`). `api/server.py` serves the build from `dist/` at `/`
and `/static`; in development the Vite dev server proxies `/api` to the same
backend instead. See [../iocbot/web/README.md](../iocbot/web/README.md).

## Storage schema — `data/state.db`

SQLite, WAL mode (`synchronous=NORMAL`, busy timeout, memory temp store). The
central `iocs` table is keyed on `(ioc_type, ioc)`, so upsert **merges** on repeat
observations: categories, tags, sources, URLs, descriptions and evidence are
unioned; `first_seen` keeps the earliest, `last_seen` the latest; `first_cycle`
is written once and never rewritten.

| Table | Purpose |
|---|---|
| `iocs` | The master record (value, type, severity, confidence, family/actor, validation, timestamps). |
| `ioc_categories` | Normalized `(type, ioc, category)` index for category filtering. |
| `iocs_fts` | FTS5 over value, family, actor, description, tags. |
| `cycles` | Collection-run history (stats JSON). |
| `folders` / `folder_iocs` | Auto + manual folders and manual membership. |
| `api_keys` | API keys (hash, prefix, scopes, platform, uses, last_ip, revoked). |
| `users` | Dashboard users (PBKDF2 `password_hash`, last login). |
| `push_log` | Outbound-push history. |
| `meta` | Key/value (e.g. one-time-backfill sentinels). |

`flag_c2` / `flag_malware` are **materialized category-view flags** on `iocs`
(backfilled once via `meta`), so the dashboard's C2 / Malware / Importable views
are cheap index scans. Severity itself is indexed, not materialized.

## Folder model

- **Auto folders** — one per distinct `malware_family` / `threat_actor`, created by
  `sync_auto_folders()` on each cycle and on API startup. Membership always follows
  the IOC's current family/actor field, so editing that field moves the IOC.
  Deleting an auto folder is rejected.
- **Manual folders** — created by analysts; membership added individually or via a
  filter. `FOLDERS_INDEX.csv` / `folders/*.csv` are written from auto folders
  (capped at 500 files).

## Four output consumers

1. **CSV export** (`export.py`) — dated daily artifacts for manual import.
2. **REST API + dashboard** (`api/server.py`) — pull endpoints for SIEMs and an
   analyst UI over the same rows. See [API.md](API.md).
3. **Outbound push** (`push.py`) — optional Splunk HEC / Elasticsearch / webhook
   delivery, off by default.
4. **Cycle summary** (`summary.py`) — the human-readable `IOC_SUMMARY.txt`.

All four read the same scored, validated rows from `data/state.db`, so a value's
status is consistent no matter how it is consumed.