# Dashboard (Vite + React + TypeScript)

The analyst dashboard. The backend is FastAPI (`python3 -m iocbot.api.server`);
this is only the front end, talking to it over `/api/v1`.

## Stack

- **Vite** (build + dev server)
- **React 19** + **TypeScript**
- **Tailwind CSS v4** (tokens in `src/index.css`)
- **Phosphor icons** (`@phosphor-icons/react`)

## Develop

Terminal 1 (backend, must be running):

```bash
cd /home/kali/ioc-intel-bot
python3 -m iocbot.api.server --host 127.0.0.1 --port 8080
```

Terminal 2 (front end, proxies `/api` to the backend):

```bash
cd iocbot/web
npm install
npm run dev          # http://localhost:5173
```

## Build (what FastAPI serves)

```bash
npm run build        # type-check (tsc -b) + emit iocbot/web/dist
```

`dist/` is served by FastAPI at `/` and `/static`. Vite's `base` is set to
`/static/` so the emitted asset URLs match the mount. `node_modules/` and
`dist/` are gitignored: rebuild from `package-lock.json`.

## Layout

```
src/
  App.tsx              shell: header, KPI strip, sidebar, IOC page, API page
  main.tsx             entry
  index.css            Tailwind theme + base styles
  lib/api.ts           typed API client (auth, search, folders, keys, users)
  lib/ui.tsx           shared primitives (badges, buttons, empty/loading states)
  components/IocTable  dense table: sort, select, paginate
  components/Drawer    IOC detail/edit panel + "add IOC" modal
  pages/Login          sign-in / register / API-key
  pages/ApiPage        API keys + dashboard users (role management)
```

## Notes

- Auth is a session or machine key in `X-API-Key`, stored in `localStorage`.
- Severity and confidence are always shown with **text**, never colour alone.
- Motion respects `prefers-reduced-motion` (global override in `index.css`).
- `--faint` is `#7D8CA0` (WCAG AA); the older value failed contrast.