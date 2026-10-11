# IOC Intelligence — SIEM Pull API

The bot serves **the same feed it exports** through an authenticated REST API at
`/api/v1` so SIEMs, analysts, and scripts can pull indicators on demand. The
dashboard at `http://127.0.0.1:8080/` talks to this same API.

For architecture, configuration, sources, and day-to-day operation see
[ARCHITECTURE.md](ARCHITECTURE.md), [CONFIGURATION.md](CONFIGURATION.md),
[SOURCES.md](SOURCES.md), and [OPERATIONS.md](OPERATIONS.md).

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

Every `/api/v1/*` request requires a key, **except** these six endpoints, which
must stay reachable before you have one:

| Unauthenticated endpoint | Why |
|---|---|
| `GET /api/v1/health` | Liveness probe |
| `GET /api/v1/auth/status` | Drives the login page (sign-in vs first-run provisioning, and whether registration is open) |
| `POST /api/v1/auth/login` | Username/password sign-in |
| `POST /api/v1/auth/register` | Self-service account creation (see **Users & roles** below) |
| `POST /api/v1/auth/provision` | One-time first-run admin account creation |
| `POST /api/v1/auth/bootstrap` | One-time bootstrap-key claim (404 after first run) |

Send a key one of three ways:

| Method | Example |
|---|---|
| Header (preferred) | `X-API-Key: iok_...` |
| Authorization | `Authorization: Bearer iok_...` |
| Query param | `?apikey=iok_...` (handy for curl / webhooks) |

Scopes: `read`, `write`, `admin`. `admin` implies `read` + `write`.

| Scope | Unlocks |
|---|---|
| `read` | `/iocs`, `/feed`, `/stats`, `/cycles`, `/health`, `/folders`, `/run` (GET), `/push` (GET), `/auth/me`, `/auth/logout` |
| `write` | IOC create/update/delete, folder create/update/delete + membership, `POST /run`, `POST /push` |
| `admin` | Everything above, plus the full `/keys` lifecycle |

A `401` means missing/invalid key; a `403` means valid but insufficient scope.
Keys are stored as SHA-256 hashes; the plaintext `iok_` + 40 hex is shown **once**
at creation. Rotate to get a new plaintext (the old key stops working).

## Users & roles

Dashboard accounts carry a **role**, and the role decides the scopes issued to
their session key:

| Role | Scopes | Can do |
|---|---|---|
| `viewer` | `read` | Search, view and export IOCs. No edits. |
| `analyst` | `read,write` | Also create, edit and delete IOCs and folders. |
| `admin` | `admin,write,read` | Everything, incl. API keys and user management. |

> **A user may pick their own role at sign-up, but `admin` is never
> self-assignable.** Anyone who can reach `POST /api/v1/auth/register` could
> otherwise grant themselves full control. Registering with `role: "admin"`
> returns **400**; an existing admin must grant it via
> `PUT /api/v1/users/{id}/role`.

### Register an account

```bash
curl -X POST http://127.0.0.1:8080/api/v1/auth/register \
  -H 'Content-Type: application/json' \
  -d '{"username":"jane","password":"longpassword","role":"analyst"}'
# -> {"ok":true,"username":"jane","role":"analyst","key":"iok_...","first_user":false}
```

The response includes a ready-to-use session key. The **first** account ever
created becomes `admin` automatically (there is no admin yet at that point, and
it replaces the old bootstrap flow). Username must be ≥ 2 chars
(letters/digits/`.`/`_`/`-`), password ≥ 8 chars, and reserved names
(`admin`, `root`, `system`, …) are rejected.

Set `auth.allow_registration: false` in `config/api.yaml` to close registration
once your accounts exist.

### Manage users (admin scope)

```bash
GET  /api/v1/users                    # list accounts + the role catalogue
PUT  /api/v1/users/{id}/role          {"role":"analyst"}
PUT  /api/v1/users/{id}/disabled      {"disabled":true}
```

Safety rails: the **last remaining admin cannot be demoted or disabled** (409),
so you can never lock every administrator out. Disabling an account also revokes
its active session, and a disabled account cannot log in. Non-admins calling
these endpoints get 403.

> Accounts that predate this feature are migrated to `admin`, preserving their
> previous (effectively full-access) behaviour.

### First-run bootstrap

On first start the server writes an admin key to `data/keys/admin.key`
(mode 0600) — only if the key table is empty. Claim it **once**, either from the
dashboard login card or:

```bash
curl -X POST http://127.0.0.1:8080/api/v1/auth/bootstrap
# -> {"name":"admin","key":"iok_..."}   (the file is deleted)
```

> While **no dashboard user exists yet**, a deleted bootstrap file is silently
> re-created on the next start, so first-run setup cannot lock itself out. Once
> an account exists, further claims return 404.

Create the first dashboard user from the login page, or via
`POST /api/v1/auth/provision` with `{"username","password"}` (username ≥ 2 chars,
password ≥ 8 chars). Passwords are stored as PBKDF2-HMAC-SHA256, 260 000
iterations. `POST /api/v1/auth/login` returns an admin-scoped **session key**
(named `session:<username>`, one active per user; logging in rotates the
previous one). `POST /api/v1/auth/logout` revokes it. `GET /api/v1/auth/me`
reports the current key's identity and method.

If auth is required but you are locked out, create another admin key locally:
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
`format=stix` to get a file-ready export. (There is no `Accept`-header handling —
the `format` query parameter is the only way to change the output type.)

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

CSV output (17 columns — the API's own richer set, which adds `CAMPAIGN`,
`MITRE_ATTACK` and `DESCRIPTION` on top of the 14 columns in `IOC_FEED.csv`):

```
IOC,IOC_TYPE,SEVERITY,CONFIDENCE,CATEGORY,MALWARE_FAMILY,THREAT_ACTOR,CAMPAIGN,
FOLDERS,VALIDATION_STATUS,CROWDSTRIKE_IMPORTABLE,FIRST_SEEN,LAST_SEEN,SOURCE,
TAGS,MITRE_ATTACK,DESCRIPTION
```

STIX returns a STIX 2.1 `indicator` bundle with `x_severity`,
`x_malware_family`, `x_threat_actor`, `x_folders`, `x_sources` custom
properties for context. Confidence maps to STIX: LOW 30, MEDIUM 50, HIGH 75,
CRITICAL 95.

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
| `ioc_type` | Filter types, comma list: `IPv4,IPv6,Domain,URL,SHA256,SHA1,MD5,Email,File-Name,File-Path,CVE,Malware,Threat-Actor,Campaign`. |
| `severity` | `CRITICAL,HIGH,MEDIUM,LOW` (comma list = OR). |
| `confidence` | `CRITICAL,HIGH,MEDIUM,LOW`. |
| `category` | Category labels present on the IOC (OR). |
| `malware_family`, `threat_actor` | Exact string matches. |
| `min_severity` | Threshold: rows at/above this severity (**single value only**). |
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

> **Gotcha:** `min_severity` takes a **single** severity level, not a comma list.
> `min_severity=HIGH,CRITICAL` is silently ignored (the value is looked up as a
> single key). To request a set, use `severity=HIGH,CRITICAL`; to request
> "this level and above", use `min_severity=HIGH`.

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
GET  /api/v1/health       # {"status":"ok","iocs":N,"version":...} — no auth
GET  /api/v1/run          # {"running":...,"last_stats":...,"last_error":...}
POST /api/v1/run          # start a collection cycle in the background (write) — returns immediately
GET  /api/v1/push         # push config + push_log tail
POST /api/v1/push         # trigger outbound push (write) — runs synchronously, may block
GET  /api/v1/auth/me      # current identity + auth method (session vs api_key)
POST /api/v1/auth/logout  # revoke the current session key
```

## Complete endpoint index

| Endpoint | Scope |
|---|---|
| `GET /api/v1/health` | none |
| `GET /api/v1/auth/status` | none |
| `POST /api/v1/auth/provision` | none (first run only) |
| `POST /api/v1/auth/login` | none |
| `POST /api/v1/auth/register` | none (unless `allow_registration: false`) |
| `POST /api/v1/auth/bootstrap` | none (first run only) |
| `GET /api/v1/auth/me` | read |
| `POST /api/v1/auth/logout` | read |
| `GET /api/v1/stats`, `/cycles` | read |
| `GET /api/v1/feed`, `/iocs`, `/iocs/{type}/{ioc}` | read |
| `GET /api/v1/folders`, `/folders/{id}`, `/folders/{id}/iocs` | read |
| `GET /api/v1/run`, `GET /api/v1/push` | read |
| `POST /api/v1/iocs`, `PUT`/`DELETE /api/v1/iocs/{type}/{ioc}` | write |
| `POST /api/v1/folders`, `PUT`/`DELETE /api/v1/folders/{id}` | write |
| `POST`/`DELETE /api/v1/folders/{id}/iocs[/{type}/{ioc}]` | write |
| `POST /api/v1/folders/sync` | write |
| `POST /api/v1/run`, `POST /api/v1/push` | write |
| `GET`/`POST /api/v1/keys`, `POST /keys/{id}/rotate`, `DELETE /keys/{id}` | admin |
| `GET /api/v1/users`, `PUT /users/{id}/role`, `PUT /users/{id}/disabled` | admin |

## Configuration (`config/api.yaml`)

```yaml
server:
  host: 0.0.0.0         # localhost + LAN; use 127.0.0.1 to keep it machine-local
  port: 8080
auth:
  required: true
  bootstrap_key_file: data/keys/admin.key
  allow_registration: true    # self-service sign-up (viewer/analyst only)
```

The dashboard is served at `/` on the same process. `auth.required: true` guards
the API but **not** the dashboard HTML itself — `/` and `/static/*` are served
without server-side auth, and the UI authenticates client-side. Serve only on
trusted hosts.

### Security notes

- **No TLS.** The server is plain HTTP; API keys travel in cleartext. Bind to
  `127.0.0.1` or terminate TLS in front of it before exposing the port.
- **Default bind is `0.0.0.0`** (LAN-reachable) via `config/api.yaml`. The code
  fallback when the file is absent is `127.0.0.1`.
- **CORS is wildcard and hardcoded** — `allow_origins=["*"]`, `allow_methods=["*"]`,
  `allow_headers=["*"]` (set in `api/server.py`, not configurable via YAML), so
  SIEM consoles and the browser can call the API directly.
- **`?apikey=` in a query string** is convenient but lands in access logs and
  browser history — prefer the `X-API-Key` header.
- **`--no-auth`** disables authentication entirely (local debugging only).
- **First-run bootstrap** hands the admin plaintext to whoever reaches
  `POST /api/v1/auth/bootstrap` while the file exists — claim it promptly.
- Per-key `uses`/`last_ip` accounting is updated at most once per 60 s, and
  `last_ip` trusts `X-Forwarded-For` unconditionally (no trusted-proxy config).

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