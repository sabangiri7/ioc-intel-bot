# IOC Intelligence Collection Bot

Collects, extracts, validates, normalizes, deduplicates, classifies, scores, and
exports threat-indicator IOCs focused on **C2 infrastructure**, **malware
distribution**, and **cracked / pirated / fake-software malware**.

Outputs are for **manual analyst review and import only**. The tool:

- never blocks anything and takes no automatic response action,
- makes **no CrowdStrike API calls** (`action=detect` is hardcoded; you import
  the CSV yourself),
- performs **no DNS resolution** of indicators and **no internal/endpoint
  queries**,
- only reads public threat-intelligence feeds, advisories, and vendor blogs.

## Requirements

Python ≥ 3.10 with: `requests beautifulsoup4 lxml feedparser tldextract PyYAML`
(installed already in this environment).

## Run

```bash
cd /home/kali/ioc-intel-bot
python3 -m iocbot.cli                 # full cycle
python3 -m iocbot.cli --json          # machine-readable stats on stdout
python3 -m iocbot.cli --sources threatfox   # only sources matching substring
python3 -m iocbot.cli --skip-reports --skip-blocklists
python3 -m iocbot.cli --max-articles 3
python3 -m iocbot.cli -v              # debug logging
```

Exit code 0 on success. Logs: `data/logs/iocbot.log`.

## Outputs — daily, dated (`output/daily/YYYY-MM-DD/`)

Each run writes that day's folder (reruns on the same day overwrite it).
Every CSV contains **one column only: `IOC`** — one indicator per line, limited
to actual indicator types: `IPv4, IPv6, Domain, URL, MD5, SHA1, SHA256, CVE`
(malware-family names, threat actors, file names/paths stay in the database
but are not exported).

| File | Contents |
|---|---|
| `MASTER_IOC_DATABASE.csv` | Every unique IOC value, all sources merged |
| `NEW_IOCS.csv` | IOC values first seen in the current cycle |
| `CROWDSTRIKE_IOC_IMPORT.csv` | Only IOC values that pass the import gate (supported type ipv4/ipv6/domain/sha256/md5, confidence+severity Medium+, validation VALID, no shared-platform/legit-service-abused tags) |
| `C2_IOCS.csv` | IOC values classified `C2` |
| `MALWARE_DOWNLOAD_IOCS.csv` | IOC values: malware distribution, loaders, stealers, cracked/fake software, ransomware, payload hosting |
| `IOC_FEED.csv` | Full feed for SIEM ingestion: `IOC, IOC_TYPE, SEVERITY, CONFIDENCE, CATEGORY, MALWARE_FAMILY, THREAT_ACTOR, FOLDERS, VALIDATION_STATUS, CROWDSTRIKE_IMPORTABLE, FIRST_SEEN, LAST_SEEN, SOURCE, TAGS` |
| `FOLDERS_INDEX.csv` | Every malware-group folder with IOC counts by severity |
| `folders/<slug>.csv` | One `IOC_FEED.csv`-format file per malware group (cap `MAX_FOLDER_FILES=500`, largest first) |
| `IOC_SUMMARY.txt` | Per-cycle human-readable report |

Example: `output/daily/2026-10-07/MASTER_IOC_DATABASE.csv`.

## Scoring model (`iocbot/score.py`)

Confidence points per distinct source: Tier A = 3, Tier B explicit = 2,
Tier B incidental = 1, Tier C = 0; +1 when ≥ 2 publishers.
≥6 → CRITICAL, ≥3 → HIGH, ≥2 → MEDIUM, else LOW.

- feed confidence < 50 caps at MEDIUM; Tier-C-only rows are always LOW/LOW.
- C2 active (≤ 30 days) → severity CRITICAL; stale C2 downgrades at 180/365 days.
- CVE rows → severity HIGH (KEV = known-exploited).
- CrowdStrike-importable = supported type ∧ `VALID` ∧ confidence and severity
  Medium+ ∧ no `shared-platform` / `legit-service-abused` / `generic-vendor` tag.
- `SHARED-PLATFORM` rows (GitHub, CDNs, shared hosting) stay master-only.

## Validation (`config/validation.yaml`)

Rejects documentation/localhost domains, unknown/reserved TLDs, private and
reserved IPs, placeholder hashes, Windows paths and filenames-as-domains;
flags shared platforms (GitHub, CDNs) and generic vendor domains.

## Sources (`config/sources.yaml`)

- **Tier A** structured feeds: ThreatFox, URLhaus, Feodo Tracker,
  MalwareBazaar, CISA KEV.
- **Tier B** reports: 15 vendor/news RSS feeds → relevance-gated article
  extraction; IOC categories/explicit flags are decided **per sentence**, not
  per article; sentences marking "legitimate …" infrastructure are tagged
  `legit-service-abused` (master-only, severity capped MEDIUM).
- **Tier C** blocklists (context-only, never importable alone): ET, CI Army,
  IPsum, DShield, ISC, OpenPhish.
- **Enrichment**: MITRE ATT&CK STIX (family/actor → technique IDs).

State: SQLite `data/state.db` (dedup merge, `first_cycle`/`last_cycle`, WAL,
indexes, FTS5 search, severity/category materialized flags).
HTTP cache: `data/cache/raw/` with stale-if-error fallback.

## Malware-group folders

Every distinct `malware_family` / `threat_actor` value becomes an **auto folder**
(synced on each cycle and on API startup). Analysts can also create **manual
folders** and add IOCs individually or by filter. Auto-folder membership always
follows the IOC's family/actor field; deleting an auto folder is rejected.
Folders appear in `IOC_FEED.csv` and as `output/daily/<date>/folders/*.csv`.

## API + dashboard (SIEM intake)

Any SIEM that holds an API key can pull the feed instead of using the CSVs:

```bash
python3 -m iocbot.api.server            # reads config/api.yaml (default 0.0.0.0:8080)
python3 -m iocbot.api.server --host 127.0.0.1 --port 8080   # localhost only
```

Full endpoint reference, auth details, formats, filters, and per-platform
ingestion hints: **see [docs/API.md](docs/API.md)**.

On first start an admin key is written to `data/keys/admin.key` (mode 0600).
Every `/api/v1/*` call must authenticate: `X-API-Key: iok_...`,
`Authorization: Bearer iok_...`, or `?apikey=...`. Scopes: `read`, `write`,
`admin` (admin implies read+write). Manage keys via the dashboard or CLI
(`--platform Splunk` records which SIEM consumes the key and drives the
dashboard's per-platform hint):

```bash
python3 -m iocbot.keys create siem-prod --scopes read,write --platform Splunk
python3 -m iocbot.keys list      # shows name/scopes/prefix/platform/uses/last_ip
python3 -m iocbot.keys rotate N
python3 -m iocbot.keys revoke N
```

Pull endpoints (auth required):

| Endpoint | Notes |
|---|---|
| `GET /api/v1/feed` | SIEM pull feed; `format=json\|csv\|stix`, `min_severity=HIGH,CRITICAL`, `view=master\|c2\|malware\|importable`, `since`, `unreviewed`, filters, `limit`, `sort`; total in `X-IOC-Total` header |
| `GET /api/v1/iocs` | Paginated search + CRUD (`POST/PUT/DELETE` per IOC); details incl. folders |
| `GET/POST/PUT/DELETE /api/v1/folders…` | Folder list/create/update/delete; `POST /folders/{id}/iocs` adds IOCs or by `{"filter": {...}}` |
| `GET /api/v1/stats`, `/api/v1/cycles`, `/api/v1/health` | Summary stats (incl. c2/malware/unreviewed counts), run history, liveness |
| `POST /api/v1/run` | Trigger a collection cycle (runs in the background) |
| `GET/POST /api/v1/push` | Inspect / trigger outbound SIEM push (see below) |

Dashboard: `http://127.0.0.1:8080/` (and `http://<lan-ip>:8080/` from other
hosts — the server binds `0.0.0.0`) — command-center layout with KPI strip,
sidebar *Views* (All / Recently Added / Critical / SIEM-Importable /
Needs Review / C2 / Malware) plus severity chips and searchable Threat Folder
browser, breadcrumbed title + summary cards, sortable intelligence table with
bulk actions, per-row menus and a threat-context panel, an **API &
Integrations** page with copy-paste pull snippets and key manager, and a
first-run bootstrap login. Serve only on trusted hosts; `auth.required: true`
guards the API but not the dashboard.

## Outbound push (optional)

For SIEMs that should receive the feed instead of polling, enable
`config/push.yaml` (Splunk HEC, Elasticsearch, or generic webhook targets):

```bash
python3 -m iocbot.push --dry-run --json    # preview what would be sent
python3 -m iocbot.push --json              # send now, results logged in push_log
```

Pushes apply the same `min_severity` / `view` gates as the API.

## Scheduling

Runs twice a day at **12:00 and 16:00**. Cron (already installed):

```cron
0 12,16 * * * cd /home/kali/ioc-intel-bot && /usr/bin/python3 -m iocbot.cli >> data/logs/cron.log 2>&1
```

or systemd user timer (`systemctl --user enable --now iocbot.timer`, units in
`deploy/`):

```ini
# ~/.config/systemd/user/iocbot.service
[Unit]
Description=IOC intelligence collection cycle (12:00 / 16:00), then push to SIEM

[Service]
Type=oneshot
WorkingDirectory=/home/kali/ioc-intel-bot
ExecStart=/usr/bin/python3 -m iocbot.cli
ExecStart=/usr/bin/python3 -m iocbot.push
```

```ini
# ~/.config/systemd/user/iocbot.timer
[Unit]
Description=Run IOC collection twice a day (12:00 and 16:00)

[Timer]
OnCalendar=*-*-* 12:00:00
OnCalendar=*-*-* 16:00:00
Persistent=true

[Install]
WantedBy=timers.target
```

## Tests

```bash
python3 -m pytest tests/ -q
```
