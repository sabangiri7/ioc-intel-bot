---
name: ioc-intel-bot-tech-stack
description: Tech stack and runtime environment for ioc-intel-bot
type: project
---

## Runtime environment
- **OS:** Windows 11 / Linux (Ubuntu), Python 3.10+
- **Node.js:** ^20.19 or ≥ 22.12 for building the dashboard (Vite 8 minimum)
- **Python deps:** requests, beautifulsoup4, lxml, feedparser, tldextract, PyYAML, fastapi, uvicorn, pydantic

## Key packages and versions (verified)
- Python: 3.14.7 (Windows)
- Node.js: 24.19.0
- Playwright: 1.64.0 (available, but chromium-cli not installed — use Playwright Python directly or npx playwright)

## Key directories
- `iocbot/` — core Python package
  - `iocbot/web/` — React/TypeScript frontend (Vite build)
- `config/` — YAML configs
- `data/` — SQLite state (never commit)
- `output/` — CSV exports (never commit)
- `tests/` — pytest suite

## Build process
1. pip install -r requirements.txt
2. cd iocbot/web && npm ci && npm run build
3. python3 -m iocbot.api.server (--no-auth for development)
