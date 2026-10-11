import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
import { Toaster } from 'sonner'
import { TooltipProvider } from './components/ui'
import './index.css'
import App from './App'
import Kitchen from './pages/Kitchen'

/**
 * Phase 1 adds a kitchen-sink route behind a hash so the existing app shell
 * keeps working untouched. Replaced by a real router in a later phase.
 */
const isKitchen = window.location.hash === '#/__kitchen'

createRoot(document.getElementById('root')!).render(
  <StrictMode>
    <TooltipProvider>
      {isKitchen ? <Kitchen /> : <App />}
      <Toaster
        theme="dark"
        position="bottom-center"
        toastOptions={{
          style: {
            background: 'var(--color-surface-3)',
            border: '1px solid var(--color-line-strong)',
            borderRadius: 6,
            color: 'var(--color-fg)',
            fontSize: 13,
          },
        }}
      />
    </TooltipProvider>
  </StrictMode>,
)
