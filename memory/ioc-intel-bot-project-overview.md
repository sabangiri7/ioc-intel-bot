---
name: ioc-intel-bot-project-overview
description: IOC Intel Bot — threat-indicator collection tool overview
type: project
---

Threat-indicator collection bot that gathers C2 infrastructure, malware distribution, and cracked/priated software IOCs from public sources; validates, scores, deduplicates, and exports them for manual analyst review.

## Stack
- Backend: Python 3.10+, FastAPI + Uvicorn, SQLite (WAL)
- Frontend: Vite 8 + React 19 + TypeScript + Tailwind v4 + Radix UI + TanStack Table
- Tests: pytest

## Safety guarantees
- Read-only design: no blocking, no CrowdStrike API calls, no DNS resolution
- Pre-commit secret scanner (`.githooks/pre-commit`)

## Key directories
- `iocbot/` — core package (pipeline, store, collectors, api, web front-end)
- `config/` — YAML configs (sources, validation, api, crowdsrike, push)
- `data/` — runtime SQLite state (NEVER commit)
- `output/` — generated CSVs (NEVER commit)

## Entry points
```bash
python3 -m iocbot.cli              # Run one collection cycle
python3 -m iocbot.api.server       # Start API + dashboard (default 0.0.0.0:8080)
python3 -m iocbot.push             # Push IOCs to SIEM targets
python3 -m iocbot.keys             # CLI for API key management
```
