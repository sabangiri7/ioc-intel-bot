# Configuration reference

All configuration lives in `config/` as YAML. No config file stores a secret
value; secrets are supplied at runtime (bootstrap admin key) or are placeholder
fields you fill in for outbound push (`targets[].token` / `.api_key` /
`.headers`). Never commit real push credentials — put them in a gitignored
`config/push.local.yaml`-style override or inject via environment/secret store.

Config files: `sources.yaml`, `validation.yaml`, `crowdstrike.yaml`, `push.yaml`,
`api.yaml`.

| File | Purpose | Read by |
|---|---|---|
| `sources.yaml` | Which sources to collect and how | `pipeline.py`, collectors |
| `validation.yaml` | False-positive rejection/flag rules | `validate.py` |
| `crowdstrike.yaml` | Falcon-import thresholds & column shape (export only) | `export.py`, `score.py` |
| `push.yaml` | Outbound SIEM targets & gating | `push.py`, `api/server.py` |
| `api.yaml` | API/dashboard bind address & auth | `api/server.py` |

---

## `config/sources.yaml`

Organized by evidence tier. The `kind` key selects a collector from the
`COLLECTORS` registry. **Relevance gating for Tier-B feeds is *not* a YAML
keyword** — it is a regex applied to article title+summary at runtime
(`classify.py:RELEVANCE_RE`). The knobs you set here are `max_articles` and
`max_age_days`.

### Tier A — structured feeds (`feeds:`)

Curated, high-confidence machine feeds. **5 configured, 5 enabled.**

| Name | URL |
|---|---|
| ThreatFox (abuse.ch) | `.../export/json/recent/` (first run pulls the **full** dump via `first_run_url`) |
| URLhaus (abuse.ch) | `.../downloads/csv_online/` |
| Feodo Tracker (abuse.ch) | `ip_url: .../ipblocklist.txt` + `browse_url` |
| MalwareBazaar (abuse.ch) | `.../export/csv/recent/` |
| CISA KEV | `known_exploited_vulnerabilities.json` |

> Feodo is the only feed that does not use a `url:` key — it has `ip_url` and
> `browse_url`.

### Tier B — reports (`reports:`)

RSS/Atom vendor/CERT/news feeds. Relevance-gated before the body is fetched.
**15 configured, 15 enabled.** Each has `max_articles` (per-cycle cap) and
`max_age_days`. Vendor/CERT sources use a 21–30 day window; general news
(Hacker News, BleepingComputer, Krebs, Help Net Security, GBHackers, HackRead)
use a tighter 14-day window.

### Tier C — blocklists (`blocklists:`)

Aggregated context feeds. **7 configured, 6 enabled** (Emerging Threats Block IPs
is `enabled: false`). Every Tier-C mention is tagged `blocklist` +
`context-only` and is capped to LOW confidence — never importable on its own.
`max_entries` truncates a list after sorting (where set).

### MITRE enrichment (`mitre:`)

A single mapping, not a list. `tier: enrichment` (deliberately not A/B/C — it
produces no IOCs). Caches `enterprise-attack.json` under `data/cache/`, refreshed
every `refresh_days` (default 30).

Full per-source table: [SOURCES.md](SOURCES.md).

---

## `config/validation.yaml`

Eight top-level keys define the false-positive gates. Lower-cased into lookup sets
at startup. Returns three outcomes:

| Status | Meaning | Importable? |
|---|---|---|
| `VALID` | Passed all gates | yes (subject to score/import gate) |
| `SHARED-PLATFORM` | Accepted but flagged shared/CDN infra | no — master only |
| `REJECTED:<reason>` | Failed a gate — stored with reason, not exported | no |

### Keys

| Key | Count | Purpose |
|---|---|---|
| `doc_domains` | 18 | RFC 2606/6761 example & documentation domains |
| `blocked_literals` | 13 | Single-label / reserved literals (`localhost`, `internal`, …) |
| `blocked_suffixes` | 12 | Reserved TLDs & suffixes (`.local`, `.test`, `.invalid`, `.onion`, `.i2p`) |
| `generic_vendor_domains` | 49 | Common vendor domains — rejected unless explicitly flagged |
| `shared_platform_domains` | 74 | Abuse-prone platforms (GitHub, CDNs, shorteners) — master only |
| `cdn_suffixes` | 43 | CDN / edge suffixes — master only |
| `placeholder_hashes` | 21 | Known dummy / empty / repeated-character hashes |
| `blocked_ip_cidrs` | 9 | Extra non-public IP ranges beyond the built-ins |

### Rejection reason codes

| Reason | Applies to | Trigger (example) |
|---|---|---|
| `syntax` | all | Wrong shape — `999.1.1.1`, `nodots`, wrong-length hash |
| `private-or-reserved` | IPv4/IPv6 | `10.0.0.5`, `127.0.0.1`, `192.0.2.1`, CGNAT, benchmark ranges |
| `localhost-or-literal` | Domain | `localhost`, `internal`, `corp` |
| `unknown-tld` | Domain | No public suffix recognized |
| `reserved-tld` | Domain | `.local`, `.test`, `.onion`, `.i2p` |
| `documentation-domain` | Domain | `example.com`, `yourdomain.com` |
| `generic-vendor` | Domain | `microsoft.com` (unless source flagged it malicious) |
| `shared-infrastructure` | Domain | `raw.githubusercontent.com`, `cdn.jsdelivr.net` (unless explicitly malicious) |
| `placeholder-hash` | hashes | Known dummy, or ≤2 distinct characters |
| `scheme` | URL | Non-`http`/`https`/`ftp` — `javascript:`, `data:` |
| `bad-year` | CVE | Year `< 1999` or in the future |
| `host-<reason>` | URL | The host fails domain/IP validation |
| `email-<reason>` | Email | The domain part fails validation |

### The `explicit_malicious` escape hatch

When a source explicitly calls a value malicious (Tier-B: the surrounding
sentence matches `MALICIOUS_SENTENCE_RE`), shared platforms / CDNs / vendor
domains flip from **rejected** to **kept + flagged** (`SHARED-PLATFORM`, or `VALID`
with a `generic-vendor` flag). They still never become CrowdStrike-importable.

Non-rejecting flags: `shared-platform`, `cdn`, `generic-vendor`, `url`,
`system-path` (`/etc`, `/proc`, `/sys`), `entity` (Malware / Threat-Actor /
Campaign).

> Extraction-side filters — treating Windows/Unix paths and file names as if they
> were indicators — live in `iocbot/extract.py`, not in this file.

---

## `config/crowdstrike.yaml`

**Export policy only.** The bot never calls the Falcon API; there is no HTTP
client pointed at a Falcon endpoint. This file describes the shape of the list
you import yourself. It contains **no keys or secrets**.

Keys actually used by the export/import gate: `confidence_threshold` and
`severity_threshold` (both `[MEDIUM, HIGH, CRITICAL]`). A row lands in
`CROWDSTRIKE_IOC_IMPORT.csv` only if its type is supported
(`IPv4, IPv6, Domain, SHA256, MD5`), validation is `VALID`, and both thresholds
pass.

Other keys in the file (`columns`, `action`, `platforms`, `expiration_days`,
`description_max_chars`, `type_map`, `severity_map`) document the intended Falcon
import format for reference; the export itself is a single-column value list.
`action: detect` is the Falcon action you would set — not a call the bot makes.

---

## `config/push.yaml`

Outbound SIEM delivery — **off by default** (`enabled: false`, `targets: []`).

| Key | Default | Meaning |
|---|---|---|
| `enabled` | `false` | Master switch |
| `min_severity` | `HIGH` | Severity floor for pushed rows |
| `view` | `importable` | Which view to push (`master`/`c2`/`malware`/`importable`) |
| `batch_limit` | `5000` | Max rows per push (newest first) |
| `targets` | `[]` | Destination list |

### Target types

| Type | Secret field(s) | Other fields | Wire format |
|---|---|---|---|
| `splunk_hec` | `token` | `url`, `sourcetype`, `verify_tls` | newline-delimited HEC events |
| `elastic` | `api_key` | `url`, `index`, `verify_tls` | newline-delimited `_bulk` NDJSON |
| `webhook` | `headers.Authorization` | `url`, `headers`, `verify_tls` | one JSON envelope per push |

Placeholders ship as `CHANGE_ME_*`. **Secret-bearing field names:** `token`,
`api_key`, and anything under `headers`. Note the examples set
`verify_tls: false` — enable verification in production. Push pulls up to
`batch_limit` newest rows per run; it does not backfill older rows.

---

## `config/api.yaml`

The API + dashboard server.

```yaml
server:
  host: 0.0.0.0     # LAN-reachable; use 127.0.0.1 to keep it machine-local
  port: 8080
auth:
  required: true    # every /api/v1 call needs a key (except the few noted below)
  bootstrap_key_file: data/keys/admin.key   # path, relative to project root
  allow_registration: true   # self-service account creation (see API.md)
```

- `host: 0.0.0.0` is the **shipped** default (reachable from the LAN). The code
  fallback when `api.yaml` is absent is `127.0.0.1`.
- `bootstrap_key_file` is a **path**, not a secret. On first start an admin key
  is generated and written there (mode 0600) if the key table is empty.
- `allow_registration` (default `true`) exposes `POST /api/v1/auth/register`.
  Registrants choose **viewer** or **analyst** only — `admin` is never
  self-assignable. Set it to `false` to close sign-up once your accounts exist.
- **Security:** the server is plain HTTP (no TLS) — API keys travel in cleartext.
  CORS is wildcard (`allow_origins=["*"]`, `allow_methods=["*"]`,
  `allow_headers=["*"]`) and hardcoded in `api/server.py` (not configurable).
  Bind to `127.0.0.1` or front it with TLS before exposing it.

---

## CLI overrides

Every entry point accepts path overrides so configs can live outside the repo:

```bash
python3 -m iocbot.cli --root /path --config-dir /path/config --data-dir /path/data --output-dir /path/out
python3 -m iocbot.api.server --config-dir /path/config
python3 -m iocbot.push --config-dir /path/config
```

Full flag reference: [OPERATIONS.md](OPERATIONS.md).