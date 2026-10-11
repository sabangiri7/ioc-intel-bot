# Operations

Running, scheduling, authentication lifecycle, and troubleshooting.

---

## Entry points

| Command | Purpose |
|---|---|
| `python3 -m iocbot.cli` | Run a collection cycle and write the daily exports |
| `python3 -m iocbot.api.server` | Serve the pull API + analyst dashboard |
| `python3 -m iocbot.push` | Push the feed to configured SIEM targets |
| `python3 -m iocbot.keys` | Manage API keys from the CLI |

---

## `iocbot.cli` — collection cycle

```bash
python3 -m iocbot.cli [options]
```

| Flag | Meaning |
|---|---|
| `--root PATH` | Project root (default: package's parent directory) |
| `--config-dir PATH` | Config directory (default `<root>/config`) |
| `--data-dir PATH` | Data directory (default `<root>/data`) |
| `--output-dir PATH` | Output directory (default `<root>/output`) |
| `--sources SUBSTR` | Only run sources whose **name** contains this string (case-insensitive) |
| `--max-articles N` | Lower the per-feed article cap for this cycle (can only *lower* the config value) |
| `--skip-reports` | Skip Tier-B RSS/article sources |
| `--skip-blocklists` | Skip Tier-C blocklists |
| `-v`, `--verbose` | Debug logging |
| `--json` | Print cycle stats as JSON instead of the summary |

Exit `0` on success, `2` if a required config file (`sources.yaml`,
`validation.yaml`, `crowdstrike.yaml`) is missing.

> **Note:** individual collector failures are caught and logged rather than
> aborting the cycle, so exit 0 does not guarantee every source succeeded — check
> `data/logs/iocbot.log` and the per-source table in `IOC_SUMMARY.txt`. Tier-A
> structured feeds always run; there is no "skip feeds" flag.

---

## `iocbot.api.server` — API + dashboard

```bash
python3 -m iocbot.api.server [options]
```

| Flag | Meaning |
|---|---|
| `--host HOST` | Bind address (default from `config/api.yaml`, else `127.0.0.1`) |
| `--port PORT` | Port (default from `config/api.yaml`, else `8080`) |
| `--config-dir PATH` | Config directory (default `<root>/config`) |
| `--no-auth` | **Disable authentication entirely.** Local debugging only. |
| `-v`, `--verbose` | Debug logging |

Precedence: `--host` > `--port` > `--no-auth` > YAML > code default.

---

## `iocbot.push` — outbound SIEM push

```bash
python3 -m iocbot.push [options]
```

| Flag | Meaning |
|---|---|
| `--config-dir PATH` | Config directory (selects `push.yaml`; the database is the project's `data/state.db`) |
| `--target NAME` | Push only this target (repeatable; matches by name) |
| `--dry-run` | Show what would be sent without sending |
| `--json` | Machine-readable result |

Applies the `min_severity` / `view` / `batch_limit` gates from `config/push.yaml`.
See [CONFIGURATION.md](CONFIGURATION.md) for the target schema.

---

## `iocbot.keys` — API key management

Local CLI; operates directly on `data/state.db` (no server needed).

```bash
python3 -m iocbot.keys create <name> --scopes read,write --platform Splunk
python3 -m iocbot.keys list [--include-revoked]
python3 -m iocbot.keys rotate <id>
python3 -m iocbot.keys revoke <id>
python3 -m iocbot.keys verify <key>
python3 -m iocbot.keys --db PATH <command> ...
```

| Command | Notes |
|---|---|
| `create NAME` | `--scopes read|write|admin` (comma list), `--platform NAME`. Plaintext shown once. |
| `list` | Shows id, name, scopes, key prefix, last-used, revoked flag. |
| `rotate ID` | Issues a new plaintext; the old key stops working immediately. |
| `revoke ID` | Revokes a key. |
| `verify KEY` | Checks a plaintext key against the store (debug aid). |

Keys are stored as SHA-256 hashes — a lost key cannot be recovered, only rotated.
`--platform` is advisory (records which SIEM consumes the key; shown in the
dashboard with an ingestion hint). Platform/uses/last-IP detail is visible via
`GET /api/v1/keys`, not in `keys list` output.

---

## Dashboard login

The dashboard at `http://<host>:<port>/` is a full single-page login screen, then
the command center. Three ways in:

1. **First run** — create the administrator account from the login page (username
   ≥ 2 chars, password ≥ 8 chars). This consumes the bootstrap admin key.
2. **Normal** — sign in with a dashboard username/password. A `session:` key is
   issued (one active session per user; logging in rotates the previous one).
3. **Advanced** — paste a machine key (`iok_…`) to open the dashboard read/write.

Bootstrap key lifecycle: on first start an admin key is written to
`data/keys/admin.key` (mode 0600) and logged once. It can be claimed via the
login page or `POST /api/v1/auth/bootstrap`. While **no user exists yet**, a
deleted bootstrap file is re-created automatically so first-run setup can't lock
itself out — once an account exists, the claim returns 404.

---

## Scheduling

Three options; pick one.

### 1. cron (local time) — installed here

```cron
0 12,16 * * * cd /home/kali/ioc-intel-bot && /usr/bin/python3 -m iocbot.cli >> data/logs/cron.log 2>&1
```

### 2. systemd user timer (local time, collect then push)

```bash
cp deploy/iocbot.service deploy/iocbot.timer ~/.config/systemd/user/
systemctl --user enable --now iocbot.timer
systemctl --user list-timers iocbot.timer
```

`deploy/iocbot.service` is `Type=oneshot` with two sequential `ExecStart=` lines
(`iocbot.cli` then `iocbot.push`) — both run, in order.

### 3. GitHub Actions (UTC)

`.github/workflows/iocbot.yml` runs at **12:00 and 16:00 UTC** and on
`workflow_dispatch`. Each run installs dependencies, collects, publishes the
cycle summary, and uploads `output/`, `data/logs/`, and `data/state.db` as a 7-day
artifact.

> **Stateless:** Actions runners do not restore the previous `state.db`, so each
> run starts from an empty database — ThreatFox pulls its **full** dump (first-run
> behavior) and cross-run `NEW_IOCS` history does not carry over. It is useful for
> producing exports on demand, not as a replacement for the local cron that feeds
> the live dashboard.

---

## Where things land

| Path | Contents |
|---|---|
| `data/state.db` | The master SQLite database |
| `data/cache/` | HTTP raw cache + MITRE bundle |
| `data/keys/admin.key` | First-run bootstrap admin key (0600, deleted after claim) |
| `data/logs/` | `iocbot.log` (+ `cron.log` when run via cron/Actions) |
| `output/daily/<date>/` | Dated CSV exports + `IOC_SUMMARY.txt` |

---

## Secret safety (pre-commit hook)

The repo ships a pre-commit secret scanner at `.githooks/pre-commit`, enabled via
`core.hooksPath` (already set in this clone). Before each commit it scans staged
files for real-looking credentials — PEM private keys, GitHub/Slack/AWS/Google
tokens, JWTs, this project's own `iok_…` keys, and high-entropy
`token`/`secret`/`password`/`api_key` assignments — and blocks the commit if it
finds one.

Documented placeholders (`CHANGE_ME`, `your_key`, `<…>`, `xxx`, `example`,
`redacted`) are deliberately ignored, so the normal codebase — which mentions
"token", "api_key", and "password" throughout its source and docs — commits
cleanly without false positives.

```bash
git config core.hooksPath .githooks   # enable (already set here)
git commit --no-verify                # emergency bypass (only if certain)
```

Runtime state (`data/`) and exports (`output/`) are gitignored and never staged.

To audit what was *ever* committed (not just staged), run the history scanner —
it walks every blob on every ref:

```bash
python3 .githooks/scan_history.py
```

This repo's history has been audited and is clean (the only match is the hook's
own private-key detection regex, which is expected). Re-run it after any history
rewrite. If it finds a real credential, rotate it immediately and purge the blob
(`git filter-repo` / BFG, then force-push).

## Troubleshooting

| Symptom | Likely cause / fix |
|---|---|
| Cycle exits 2 | A required config file is missing from `--config-dir`. |
| Exit 0 but few/no new IOCs | A collector failed silently — check `data/logs/iocbot.log` and the per-source table in `IOC_SUMMARY.txt`. |
| `NEW_IOCS.csv` contains everything | Running against an empty/fresh `state.db` (first run, or Actions without restored state) — `first_cycle` has no history. |
| `Needs Review` / `unreviewed` is empty | Nothing writes `UNVERIFIED` validation today; use `validation_status` filters instead. |
| Dashboard shows the login page on a LAN host | The dashboard HTML is served without server-side auth — sign in. Ensure `host` is reachable and not firewalled. |
| `401` from the API | Missing/invalid key, wrong scope, or a revoked/rotated key. Check `X-API-Key` / `Bearer` / `?apikey=`. |
| `403` from the API | The key lacks the required scope (`read`/`write`/`admin`). |
| Push sends nothing | `push.yaml` has `enabled: false` or no targets; or the row count matches nothing at the `view`/`min_severity` gate. Use `--dry-run --json`. |
| Push only sends the newest N rows | `batch_limit` caps each push (newest first). Lower `min_severity` or raise `batch_limit` for backfill. |
| A family folder looks stale | Auto folders are created, never garbage-collected; they persist after a family stops appearing. |
| Dashboard won't bind | Another process holds the port; change `--port`. |

See [API.md](API.md) for endpoint-level behavior and [CONFIGURATION.md](CONFIGURATION.md)
for every config key.