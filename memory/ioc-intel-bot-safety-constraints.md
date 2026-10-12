---
name: ioc-intel-bot-safety-constraints
description: Safety guarantees and security constraints for ioc-intel-bot
type: project
---

## Safety guarantees
- **No response action** — tool produces text only, never blocks or contains
- **No CrowdStrike API calls** — crowdsrike.yaml only describes export shape; action: detect is a column value, not a call
- **No DNS resolution or internal queries** — indicators stored as text, never looked up
- **Public sources only** — configured feeds are open threat-intelligence sites

## Security posture
- Dashboard served via plain HTTP (no TLS) — bind to 127.0.0.1 or use TLS front-end
- CORS wildcard: allow_origins=["*"] (hardcoded, not configurable)
- Auth: X-API-Key header, Authorization: Bearer, or ?apikey= query param
- Passwords: PBKDF2 with 260k iterations
- API keys: SHA-256 hashes stored; plaintext shown once at creation

## Pre-commit
- `.githooks/pre-commit` scans for secrets before every commit
- Historical scan: `scan_history.py` for history audit

## Important paths to never commit
- `data/` — state.db (hundreds of MB), keys, passwords
- `output/` — generated exports
- `config/*.local.yaml`, `config/secrets.yaml`, `.env` — runtime secrets
- `iocbot/web/node_modules/`, `iocbot/web/dist/` — build artifacts
