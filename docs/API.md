# IOC Intelligence — SIEM Pull API

The bot serves **the same feed it exports** through an authenticated REST API at
`/api/v1` so SIEMs, analysts, and scripts can pull indicators on demand. The
dashboard at `http://127.0.0.1:8080/` talks to this same API.

## Quick start

```bash
# start the server (reads config/api.yaml; default 0.0.0.0:8080 = localhost + LAN)
python3 -m iocbot.api.server

# grab your first key (admin, shown once) or claim the bootstrap key from the
# login page / this endpoint (first run only)
python3 -m iocbot.keys create siem-prod --scopes read --platform Splunk

# pull
curl -H "X-API-Key: iok_..." "http://127.0.0.1:8080/api/v1/iocs?format=csv&min_severity=HIGH"
```

## Authentication

Every `/api/v1/*` request (except `GET /health` and the one-time bootstrap
claim) requires a key. Send it one of three ways:

| Method | Example |
|---|---|
| Header (preferred) | `X-API-Key: iok_...` |
| Authorization | `Authorization: Bearer iok_...` |
| Query param | `?apikey=iok_...` (handy for curl / webhooks) |

Scopes: `read`, `write`, `admin`. `admin` implies `read` + `write`.
`read` unlocks search/feed/export/keys-listing*; `write` unlocks CRUD, folder
membership, `POST /run` and `POST /push`; key lifecycle requires `admin`.
\* listing keys requires `admin`.

Keys are stored as SHA-256 hashes; the plaintext `iok_...+40 hex` is shown
**once** at creation. Rotate to get a new plaintext (old key stops working).

### First-run bootstrap

On first start the server writes an admin key to `data/keys/admin.key`
(mode 0600). Claim it **once** — either from the dashboard login card or:

```bash
curl -X POST http://127.0.0.1:8080/api/v1/auth/bootstrap
# -> {"name":"admin","key":"iok_..."}   (the file is deleted; 404 on later calls)
```

If it is already claimed, create another admin key locally with
`python3 -m iocbot.keys create NAME --scopes read,write,admin`.

## Key management

CLI (local, no auth needed):

```bash
python3 -m iocbot.keys create splunk-prod --scopes read --platform Splunk
python3 -m iocbot.keys create qradar          --scopes read,write
python3 -m iocbot.keys list
python3 -m iocbot.keys rotate 3
python3 -m iocbot.keys revoke 3
```

Over the API (`admin` only):

```bash
POST   /api/v1/keys                     {"name": "...", "scopes": "read", "platform": "FortiSIEM"}
GET    /api/v1/keys?include_revoked=true
POST   /api/v1/keys/{id}/rotate         -> {"id","name","key"}  (new plaintext, once)
DELETE /api/v1/keys/{id}                revoke
```

Keys record `uses`, `last_ip` and `platform`. The `platform` field is advisory —
it tells analysts which SIEM consumes a key and is used by the dashboard to show
an ingestion hint. Common values: `Splunk`, `Elastic`, `Wazuh`, `FortiSIEM`,
`CrowdStrike`, `QRadar`, `Sentinel`, `Other`.

## Pull endpoints

### `GET /api/v1/iocs` — search + export

The workhorse endpoint. Returns paginated JSON by default; pass `format=csv` or
`format=stix` to get a file-ready export (the `format` query param overrides the
Accept header).

```bash
curl -H "X-API-Key: iok_..." "http://127.0.0.1:8080/api/v1/iocs?limit=50&format=json"
curl -H "X-API-Key: iok_..." "http://127.0.0.1:8080/api/v1/iocs?format=csv&min_severity=HIGH&view=importable"
curl -H "X-API-Key: iok_..." "http://127.0.0.1:8080/api/v1/iocs?format=stix"
```

JSON response:

```json
{
  "total": 158012,
  "limit": 50,
  "offset": 0,
  "items": [
    {
      "ioc": "1.2.3.4", "ioc_type": "IPv4",
      "severity": "CRITICAL", "confidence": "HIGH",
      "categories": ["C2"], "malware_family": "Mirai", "threat_actor": "",
      "folders": ["Mirai"], "validation_status": "VALID",
      "crowdstrike_importable": "YES", "first_seen": "2026-09-01",
      "last_seen": "2026-10-07", "sources": ["ThreatFox"], "tags": []
    }
  ]
}
```

CSV columns (also `IOC_FEED.csv`):

```
IOC,IOC_TYPE,SEVERITY,CONFIDENCE,CATEGORY,MALWARE_FAMILY,THREAT_ACTOR,CAMPAIGN,
FOLDERS,VALIDATION_STATUS,CROWDSTRIKE_IMPORTABLE,FIRST_SEEN,LAST_SEEN,SOURCE,
TAGS,MITRE_ATTACK,DESCRIPTION
```

STIX returns a STIX 2.1 `indicator` bundle with `x_severity`,
`x_malware_family`, `x_threat_actor`, `x_folders`, `x_sources` custom
properties for context.

### `GET /api/v1/feed` — SIEM pull feed

Same search engine as `/api/v1/iocs`, but defaults to `limit=1000`, always
returns the total (`body.total` for JSON, `X-IOC-Total` header for all
formats), and is what the dashboard "Pull feed" snippets use:

```bash
curl -H "X-API-Key: iok_..." "http://127.0.0.1:8080/api/v1/feed?format=json&min_severity=HIGH&view=importable"
curl -H "X-API-Key: iok_..." "http://127.0.0.1:8080/api/v1/feed?format=csv&q=asyncrat"
```

### Single IOC

```bash
GET /api/v1/iocs/{ioc_type}/{ioc}
# e.g. GET /api/v1/iocs/Domain/evil.example.com
#      GET /api/v1/iocs/SHA256/<hash>          (paths are URL-encoded)
```

Returns the full record including `categories`, `sources`,
`sources_detail`, `evidence`, upload/update fields, and folder membership.

## Query parameters

Applied to both `/api/v1/iocs` and `/api/v1/feed`.

| Param | Meaning |
|---|---|
| `q` | Full-text search over value, family, actor, description, tags (FTS5). |
| `ioc_type` | Filter types, comma list: `IPv4,IPv6,Domain,URL,SHA256,SHA1,MD5,Email,File-Name,CVE,Malware,Threat-Actor,Campaign`. |
| `severity` | `CRITICAL,HIGH,MEDIUM,LOW` (comma list = OR). |
| `confidence` | `CRITICAL,HIGH,MEDIUM,LOW`. |
| `category` | Category labels present on the IOC (OR). |
| `malware_family`, `threat_actor` | Exact string matches. |
| `min_severity` | Threshold: rows at/above this severity (adds to `severity`). |
| `validation` | Exact `validation_status` value. |
| `unreviewed` | `true` → only rows with empty/`UNVERIFIED` validation (a.k.a. Needs Review). |
| `importable` | `true` → only `crowdstrike_importable=YES`. |
| `view` | `master` (all) · `c2` · `malware` · `importable`. |
| `folder_id` | Restrict to a folder's members (auto or manual). |
| `since` | `updated_at > value` (ISO date or SQL datetime). |
| `seen_since` | `last_seen >= value`. |
| `sort` | `ioc, ioc_type, severity, confidence, first_seen, last_seen, updated_at, malware_family, threat_actor`. |
| `order` | `asc` or `desc` (default `desc`). |
| `limit` | 1–5000 (default 100 for `/iocs`, 1000 for `/feed`). |
| `offset` | Page offset. |
| `format` | `json` (default), `csv`, `stix`. |

```bash
# secrets: pull everything CrowdStrike-importable, severity HIGH+, last seen this month
curl -H "X-API-Key: iok_..." \
  "http://127.0.0.1:8080/api/v1/feed?format=csv&min_severity=HIGH&view=importable&seen_since=2026-10-01"
```

## Folders

```bash
GET    /api/v1/folders?include_zero=false     # list (auto + manual), counts
POST   /api/v1/folders                        # {"name","description","color"} -> 201
GET    /api/v1/folders/{id}                   # folder detail + counts
PUT    /api/v1/folders/{id}                   # rename / edit description
DELETE /api/v1/folders/{id}                   # manual folders only (409 for auto)
GET    /api/v1/folders/{id}/iocs              # members (same filters as /iocs)
POST   /api/v1/folders/{id}/iocs              # add: {"iocs":[{"ioc_type","ioc"}]} or {"filter":{...}}
DELETE /api/v1/folders/{id}/iocs/{type}/{ioc} # remove membership
POST   /api/v1/folders/sync                   # rebuild auto folders from family/actor
```

Auto folders derive from `malware_family` / `threat_actor` and always reflect
the IOC's current fields — editing those fields moves the IOC, deleting an auto
folder is rejected. Manual folders hold explicit membership added via
`POST .../iocs`.

## Operations

```bash
GET  /api/v1/stats        # totals, by_severity/confidence/type/category/validation,
                          # importable, new_today, c2, malware, unreviewed, folders, last_cycle
GET  /api/v1/cycles       # recent collection runs
GET  /api/v1/health       # {"status":"ok","iocs":N} — no auth
POST /api/v1/run          # start a collection cycle in the background (write)
GET  /api/v1/run          # {"running":...,"last_stats":...,"last_error":...}
GET  /api/v1/push         # push config + push_log tail
POST /api/v1/push         # trigger outbound push (write)
```

## Configuration (`config/api.yaml`)

```yaml
server:
  host: 0.0.0.0         # localhost + LAN; use 127.0.0.1 to keep it machine-local
  port: 8080
auth:
  required: true
  bootstrap_key_file: data/keys/admin.key
```

The dashboard is served at `/` on the same process. `auth.required: true` guards
the API but not the dashboard HTML itself — serve only on trusted hosts and keep
the key out of scripts that don't need it.

## Ingestion hints by platform

| Platform | Recommended pattern |
|---|---|
| Splunk | Scripted input / scheduled search curling the CSV feed, or poll from Dashboards |
| Elastic | Logstash `http_poller` / Elastic Agent on the JSON feed, `X-API-Key` header |
| Wazuh | command `localfile` curling the CSV feed; match indicator values |
| FortiSIEM | HTTP worker/reference collection on the CSV; map IOC/SEVERITY/CATEGORY/MALWARE_FAMILY |
| CrowdStrike | Use **outbound push** (config/push.yaml) — Falcon is push-based, not pull |
| QRadar | Custom property / store-&-collect HTTP source on the JSON feed |
| Sentinel | Logic App / custom connector on the JSON or STIX feed |

See `config/push.yaml` for the outbound alternative used by CrowdStrike or
SIEMs that can't poll.