# IOC Intel — Threat-Indicator Collection Bot

Collects, extracts, validates, normalizes, deduplicates, classifies, scores, and
exports threat-indicator IOCs focused on **C2 infrastructure**, **malware
distribution**, and **cracked / pirated / fake-software malware**.

Everything it produces is meant for **manual analyst review and import**. The tool
is a collector and a preparation surface — not a response engine.

## What this is / what it is not

This bot sits between public threat-intelligence feeds and a human analyst. It
gathers indicators, cleans them up, scores their confidence, and writes them out
for review. It is **deliberately not** an automated defense.

| It does | It does not |
|---|---|
| Read public feeds, advisories, and vendor blogs | Read anything internal, authenticated, or private |
| Extract, normalize, deduplicate, score IOCs | Block, quarantine, contain, or respond to anything |
| Write CSV / API / STIX exports for review | Call any endpoint-management or SIEM write API |
| Emit a CrowdStrike-import candidate list | Call the CrowdStrike Falcon API |
| — | Resolve DNS or probe the indicators |
| — | Make enforcement decisions on its own |

**Safety guarantees, and how they hold:**
- **No response action.** Nothing is blocked or contained. The tool produces text.
- **No CrowdStrike API calls.** There is no HTTP client in this codebase pointed at
  a Falcon endpoint. `config/crowdstrike.yaml` only describes the *shape* of the
  export you import yourself; `action: detect` in that file is a column value you
  would set in Falcon, not a call the bot makes.
- **No DNS resolution, no internal queries.** Indicators are stored as text and
  never looked up.
- **Public sources only.** Configured feeds are open threat-intelligence sites.

If you need automatic blocking, this is the wrong tool — feed its exports into a
system built for that, after review.

## Requirements

Python ≥ 3.10.

```bash
pip install -r requirements.txt
```

- **Collector:** `requests beautifulsoup4 lxml feedparser tldextract PyYAML`
- **API + dashboard:** `fastapi uvicorn pydantic`

## Run

```bash
cd /home/kali/ioc-intel-bot
python3 -m iocbot.cli                 # full collection cycle
python3 -m iocbot.cli --json          # machine-readable stats on stdout
python3 -m iocbot.cli --sources threatfox   # only sources matching a substring
python3 -m iocbot.cli --skip-reports --skip-blocklists
python3 -m iocbot.cli --max-articles 3
python3 -m iocbot.cli -v              # debug logging
```

Exit code 0 on success, 2 if a required config file is missing. Logs:
`data/logs/iocbot.log`. See **[docs/OPERATIONS.md](docs/OPERATIONS.md)** for the
complete flag reference.

## Documentation map

| Document | What it covers |
|---|---|
| **[docs/ARCHITECTURE.md](docs/ARCHITECTURE.md)** | Data flow, module map, storage schema, folder model |
| **[docs/CONFIGURATION.md](docs/CONFIGURATION.md)** | Every config file and key, with security notes |
| **[docs/SOURCES.md](docs/SOURCES.md)** | All 28 configured sources by tier, MITRE enrichment |
| **[docs/API.md](docs/API.md)** | Full SIEM pull-API + dashboard endpoint reference |
| **[docs/OPERATIONS.md](docs/OPERATIONS.md)** | Running, scheduling, key/user lifecycle, troubleshooting |

## Outputs — daily, dated (`output/daily/YYYY-MM-DD/`)

Each run writes that day's folder (reruns on the same day overwrite the same
filenames). Outputs hold actual indicator values only — malware-family names,
threat actors, campaigns, and file names/paths live in the database but are not
exported here. Exported types: `IPv4, IPv6, Domain, URL, MD5, SHA1, SHA256, CVE`.

| File | Shape | Contents |
|---|---|---|
| `MASTER_IOC_DATABASE.csv` | one column (`IOC`) | Every unique IOC value, all sources merged |
| `NEW_IOCS.csv` | one column (`IOC`) | IOC values first seen in the current cycle |
| `CROWDSTRIKE_IOC_IMPORT.csv` | one column (`IOC`) | Only values that pass the import gate (see below) |
| `C2_IOCS.csv` | one column (`IOC`) | Values classified `C2` |
| `MALWARE_DOWNLOAD_IOCS.csv` | one column (`IOC`) | Distribution, loaders, stealers, cracked/fake software, ransomware, payload hosting |
| `IOC_FEED.csv` | 14 columns | Full feed for SIEM ingestion (see header below) |
| `FOLDERS_INDEX.csv` | 6 columns | Every malware-group folder with IOC counts by severity |
| `folders/<slug>.csv` | 14 columns | One `IOC_FEED.csv`-format file per group (cap 500 files, largest first) |
| `IOC_SUMMARY.txt` | prose | Per-cycle human-readable report |

> **On the "one column" rule:** the five value lists (`MASTER`, `NEW`,
> `CROWDSTRIKE`, `C2`, `MALWARE_DOWNLOAD`) are a single `IOC` column — one
> indicator per line. The *rich* files (`IOC_FEED.csv`, `folders/*.csv`,
> `FOLDERS_INDEX.csv`) carry additional metadata columns.

`IOC_FEED.csv` columns:
`IOC, IOC_TYPE, SEVERITY, CONFIDENCE, CATEGORY, MALWARE_FAMILY, THREAT_ACTOR, FOLDERS, VALIDATION_STATUS, CROWDSTRIKE_IMPORTABLE, FIRST_SEEN, LAST_SEEN, SOURCE, TAGS`

## Scoring model (`iocbot/score.py`)

**Confidence** — points per distinct source: Tier A = 3, Tier B explicit = 2,
Tier B incidental = 1, Tier C = 0; **+1** when ≥ 2 publishers.
≥6 → CRITICAL, ≥3 → HIGH, ≥2 → MEDIUM, else LOW.

**Severity** — evaluated in order:

1. **CVE** → HIGH (confidence bumped to HIGH if Tier-A or ≥2 publishers).
2. **C2** → CRITICAL if active or ≤30 days old; HIGH (31–180d); MEDIUM (>180d); LOW (>365d).
3. **Ransomware** with a Tier-A source → HIGH; any explicit-malware/C2 source → HIGH.
4. Otherwise tracks confidence: MEDIUM confidence → MEDIUM, else LOW.
5. Staleness decay applies to **all** rows: MEDIUM/HIGH older than 180d → MEDIUM; older than 365d → LOW.
6. Tier-C-only rows are forced LOW/LOW; LOW confidence forces LOW severity.

**Import gate** — a row is CrowdStrike-importable when it is a supported type
(`IPv4, IPv6, Domain, SHA256, MD5`), validation `VALID`, confidence and severity
Medium+, and carries none of the tags `shared-platform`, `legit-service-abused`,
`generic-vendor`, or `cdn`. Legitimate-but-abused infrastructure and CDNs are
kept in the master dataset but never importable.

> In practice most rows land HIGH: Tier-A feeds dominate and multi-publisher
> corroboration is common. Read CRITICAL as "act first," not "the only thing that
> matters."

## Validation (`config/validation.yaml`)

Indicators are gated to suppress false positives. Rejections are typed
(`REJECTED:<reason>`); `SHARED-PLATFORM` is a *keep but flag* outcome, not a
rejection. `config/validation.yaml` rejects documentation domains, unknown or
reserved TLDs (including `.onion`/`.i2p`), private and reserved IPs, placeholder
hashes, bad CVE years, and non-HTTP URL schemes. Shared platforms, CDNs, and
generic vendor domains are rejected **unless** the source explicitly called the
value malicious, in which case they are kept and flagged. Extraction-side filters
(Windows/Unix paths, filenames mistaken for domains) live in `iocbot/extract.py`.
Full reason-code table: **[docs/CONFIGURATION.md](docs/CONFIGURATION.md)**.

## Sources

28 configured sources across three evidence tiers — see
**[docs/SOURCES.md](docs/SOURCES.md)** for the complete table.

- **Tier A** structured feeds (high confidence): ThreatFox, URLhaus, Feodo
  Tracker, MalwareBazaar, CISA KEV.
- **Tier B** reports (relevance-gated): 15 vendor/CERT/news RSS feeds →
  per-sentence IOC extraction and classification.
- **Tier C** blocklists (context only, never importable alone): ET, CI Army,
  IPsum, DShield, ISC, OpenPhish.
- **Enrichment:** MITRE ATT&CK STIX maps family/actor → technique IDs.

## Storage

State lives in SQLite `data/state.db`: deduplicating upsert (merge on
`(ioc_type, ioc)`), `first_cycle`/`last_cycle` provenance, WAL, indexes, FTS5
search, and materialized C2/malware category-view flags. HTTP responses are cached
in `data/cache/raw/` with stale-if-error fallback.

## Malware-group folders

Every distinct `malware_family` / `threat_actor` becomes an auto folder, synced on
each cycle and on API startup; membership always follows the IOC's family/actor
field. Analysts can also create manual folders and add IOCs individually or by
filter. Deleting an auto folder is rejected. Folders appear in `IOC_FEED.csv` and
as `output/daily/<date>/folders/*.csv`.

## API + dashboard (SIEM intake)

Any SIEM holding an API key can pull the feed instead of using the CSVs.

```bash
python3 -m iocbot.api.server            # reads config/api.yaml (default 0.0.0.0:8080)
python3 -m iocbot.api.server --host 127.0.0.1 --port 8080   # localhost only
```

Full endpoint reference, formats, filters, and per-platform ingestion hints:
**[docs/API.md](docs/API.md)**.

Every `/api/v1/*` call requires a key — `X-API-Key: iok_...`,
`Authorization: Bearer iok_...`, or `?apikey=...` — except the unauthenticated
`health`, `auth/status`, and one-time `auth/bootstrap` / `auth/login` /
`auth/provision` calls. Scopes: `read`, `write`, `admin` (admin implies
read + write). On first start an admin key is written to `data/keys/admin.key`
(mode 0600). Manage keys via the dashboard or CLI:

```bash
python3 -m iocbot.keys create siem-prod --scopes read,write --platform Splunk
python3 -m iocbot.keys list
python3 -m iocbot.keys rotate N
python3 -m iocbot.keys revoke N
```

Dashboard: `http://127.0.0.1:8080/` — a command-center layout with KPI strip,
sidebar views (All / Recently Added / Critical / SIEM-Importable / Needs Review /
C2 / Malware), severity chips, a searchable Threat Folder browser, a sortable
intelligence table with bulk actions, an **API & Integrations** page, and a
first-run bootstrap login. The dashboard HTML itself is served without
server-side auth; the API behind it is protected. Serve only on trusted hosts.

### Security posture (read before exposing this)

- The server speaks **plain HTTP** — API keys travel in cleartext. Bind to
  `127.0.0.1` or front it with TLS before putting it on a network you don't
  control.
- The shipped default bind is `0.0.0.0` (LAN-reachable). The code fallback when
  `api.yaml` is absent is `127.0.0.1`.
- CORS is **wildcard** (`allow_origins=["*"]`) and hardcoded, to let SIEM
  consoles and the browser talk to the API. Not configurable.
- `--no-auth` disables authentication entirely. Local debugging only.
- Keys are stored as SHA-256 hashes; plaintext is shown once at creation.

## Outbound push (optional)

For SIEMs that should receive the feed instead of polling, enable
`config/push.yaml` (Splunk HEC, Elasticsearch, or generic webhook):

```bash
python3 -m iocbot.push --dry-run --json    # preview what would be sent
python3 -m iocbot.push --json              # send now; results in push_log
```

Push applies the same `min_severity` / `view` gates as the API. It is off by
default (`enabled: false`, no targets). Push pulls up to `batch_limit` rows
(newest first) per run — it does not backfill older rows automatically.

## Scheduling

Runs **twice a day at 12:00 and 16:00**. Three options:

- **cron** (installed here; local time):
  ```cron
  0 12,16 * * * cd /home/kali/ioc-intel-bot && /usr/bin/python3 -m iocbot.cli >> data/logs/cron.log 2>&1
  ```
- **systemd user timer** (`systemctl --user enable --now iocbot.timer`; units in
  `deploy/` — runs collect then push, on local time).
- **GitHub Actions** (`.github/workflows/iocbot.yml`, 12:00 & 16:00 **UTC**;
  also `workflow_dispatch`). Each run collects and uploads `output/`, logs, and
  `state.db` as a 7-day artifact. Note: Actions runs are **stateless** — no prior
  `state.db` is restored, so cross-run `NEW_IOCS` history does not carry over.

## Tests

```bash
python3 -m pytest tests/ -q
```