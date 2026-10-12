---
name: ioc-intel-bot-run-skill
description: Status of the /run-ioc-intel-bot skill being built
type: project
---

A skill was built at `.claude/skills/run-ioc-intel-bot/` to drive the app.

## What was built
- `CLAUDE.md` at repo root (auto-loaded context)
- `memory/` directory with 6 memory files covering:
  - Project overview, tech stack, pipeline architecture, tier system, safety constraints
- `docs/CODEBASE.md` — complete technical reference

## App state (verified)
- Server runs at http://127.0.0.1:8080 with --no-auth flag
- Health endpoint: `{"status":"ok","iocs":0,"version":"1.0.0"}`
- Dashboard loads (Vite + React build in dist/)
- Web app accessible at root path
- Database is empty (0 IOCs) — ready for first collection run

## Build commands verified
```bash
pip install -r requirements.txt          # installed
cd iocbot/web && npm ci && npm run build # dist/ generated
python3 -m iocbot.api.server --no-auth   # server starts
```
