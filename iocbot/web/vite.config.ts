import tailwindcss from '@tailwindcss/vite'
import react from '@vitejs/plugin-react'
import { defineConfig } from 'vite'

// The dashboard is served by the FastAPI server (python3 -m iocbot.api.server),
// which mounts the production build from `dist/`. During `npm run dev` Vite runs
// its own dev server and proxies /api to that same FastAPI process, so the UI
// talks to a real backend with no CORS setup.
export default defineConfig({
  // FastAPI serves the built dashboard from the /static mount, so emitted asset
  // URLs must live under /static rather than at the site root.
  base: '/static/',
  plugins: [react(), tailwindcss()],
  server: {
    port: 5173,
    proxy: {
      '/api': { target: 'http://127.0.0.1:8080', changeOrigin: true },
    },
  },
  build: {
    outDir: 'dist',
    emptyOutDir: true,
  },
})