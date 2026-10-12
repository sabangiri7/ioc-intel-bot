---
name: ioc-intel-bot-pipeline-architecture
description: Pipeline architecture and data flow for ioc-intel-bot
type: project
---

## Pipeline flow (single cycle)
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
```

## Config loading
- sources.yaml: feeds, blocklists, reports, mitre sections
- validation.yaml: false-positive gates (doc domains, reserved TLDs, IP ranges, bad CVEs)
- crowdsrike.yaml: export shape (confidence/severity thresholds, type lists)
- api.yaml: server host/port, auth settings, bootstrap key file

## Database schema (state.db)
- `iocs` table: core IOC records (PK: ioc_type + ioc)
- `ioc_categories` table: category normalization index
- `iocs_fts` table: FTS5 full-text search
- `cycles` table: collection-run history
- `folders` / `folder_iocs` tables: manual and auto folder membership
- `api_keys` table: API keys and session tokens
- `users` table: dashboard users with PBKDF2 passwords
- `push_log` table: outbound push history
- `meta` table: one-time backfill sentinels

## Flow details
1. **Collect**: Iterate over sources.yaml feeds → collectors generate Mention lists
2. **Validate**: Each mention passes validation.yaml gates → VALID/SHARED-PLATFORM/REJECTED
3. **Normalize**: Canonicalize values (domain lowercasing, URL port/fragment removal, etc.)
4. **Store**: Upsert into SQLite (merge on ioc_type+ioc, union categories/tags/sources)
5. **Score**: Confidence + severity from tier points, explicit flags, staleness decay
6. **Export**: Write CSV artifacts, folder buckets, summary
