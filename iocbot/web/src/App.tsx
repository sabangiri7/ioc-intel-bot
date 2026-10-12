import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import {
  ShieldCheck,
  Search as MagnifyingGlass,
  Play,
  KeyRound as Key,
  LogOut as SignOut,
  Plus,
  RefreshCw as ArrowClockwise,
  Columns3 as Columns,
} from 'lucide-react'
import {
  api,
  downloadUrl,
  getKey,
  onUnauthorized,
  setKey,
  type Folder,
  type Ioc,
  type SearchFilters,
  type Stats,
} from './lib/api'
import { Button, ErrorText, Toast, num } from './lib/ui'
import Login from './pages/Login'
import ApiPage from './pages/ApiPage'
import FolderManager from './pages/FolderManager'
import IocTable, { COLUMNS, rowKey } from './components/IocTable'
import Drawer, { NewIocModal } from './components/drawer/Drawer'

type ViewKey = 'all' | 'recent' | 'critical' | 'importable' | 'review' | 'c2' | 'malware'

const VIEWS: Record<ViewKey, { title: string; desc: string }> = {
  all: { title: 'All IOCs', desc: 'Every indicator currently in the intelligence base.' },
  recent: { title: 'Recently Added', desc: 'Indicators first seen in the most recent cycles.' },
  critical: { title: 'Critical', desc: 'Indicators scored CRITICAL severity. Highest priority.' },
  importable: {
    title: 'SIEM-Importable',
    desc: 'Indicators that pass the import gate for CrowdStrike Falcon.',
  },
  review: { title: 'Needs Review', desc: 'Indicators without a validation verdict.' },
  c2: { title: 'C2 Infrastructure', desc: 'Command-and-control servers and domains.' },
  malware: { title: 'Malware Distribution', desc: 'Distribution, loaders, stealers and payload hosting.' },
}

const SEVERITIES = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'] as const
const PAGE_SIZES = [50, 100, 250, 500]

// Value groups offered by the export selector. Empty string = every type.
const EXPORT_TYPES: Record<string, string[]> = {
  ip: ['IPv4', 'IPv6'],
  hash: ['SHA256', 'SHA1', 'MD5'],
  domain: ['Domain'],
  url: ['URL'],
}
const EXPORT_LIMIT = 5000

export default function App() {
  const [authed, setAuthed] = useState(Boolean(getKey()))
  const [page, setPage] = useState<'iocs' | 'folders' | 'api'>('iocs')
  const [stats, setStats] = useState<Stats | null>(null)
  const [folders, setFolders] = useState<Folder[]>([])
  const [rows, setRows] = useState<Ioc[]>([])
  const [total, setTotal] = useState(0)
  const [loading, setLoading] = useState(false)
  const [loadError, setLoadError] = useState('')
  const [notice, setNotice] = useState<{ message: string; error?: boolean } | null>(null)

  const [view, setView] = useState<ViewKey>('all')
  const [q, setQ] = useState('')
  const [severities, setSeverities] = useState<Set<string>>(new Set())
  const [folder, setFolder] = useState<Folder | null>(null)
  const [sort, setSort] = useState('last_seen')
  const [order, setOrder] = useState<'asc' | 'desc'>('desc')
  const [limit, setLimit] = useState(50)
  const [offset, setOffset] = useState(0)
  const [exportType, setExportType] = useState('')
  const [hiddenColumns, setHiddenColumns] = useState<string[]>(() =>
    JSON.parse(localStorage.getItem('ioc_hide_cols') ?? '[]'),
  )
  const [selection, setSelection] = useState<Set<string>>(new Set())
  const [selected, setSelected] = useState<Ioc | null>(null)
  const [showNew, setShowNew] = useState(false)
  const [showColumns, setShowColumns] = useState(false)
  const [search, setSearch] = useState('')
  const [folderSearch, setFolderSearch] = useState('')
  const searchRef = useRef<HTMLInputElement>(null)

  const notify = useCallback((message: string, error?: boolean) => {
    setNotice({ message, error })
    setTimeout(() => setNotice(null), error ? 5000 : 2500)
  }, [])

  const filters: SearchFilters = useMemo(() => {
    const f: SearchFilters = { limit, offset, sort, order, view }
    if (q.trim()) f.q = q.trim()
    if (folder) f.folder_id = folder.id
    if (severities.size) f.severity = [...severities]
    if (view === 'recent') f.since = new Date(Date.now() - 7 * 86400_000).toISOString().slice(0, 10)
    if (view === 'review') f.q = f.q ?? ''
    return f
  }, [limit, offset, sort, order, view, q, folder, severities])

  const loadStats = useCallback(async () => {
    try {
      setStats(await api.stats())
    } catch {
      /* stats are decorative; a failure must not block the table */
    }
  }, [])

  const loadFolders = useCallback(async () => {
    try {
      const r = await api.folders(false)
      setFolders(r.items)
    } catch {
      setFolders([])
    }
  }, [])

  const effectiveFilters = useCallback((): SearchFilters => {
    // Turn the sidebar "view" into concrete query params so both the table and
    // the CSV export ask the API for exactly the same rows.
    const f: SearchFilters = { ...filters }
    if (view === 'critical') {
      f.severity = ['CRITICAL']
    } else if (view === 'importable') {
      f.view = 'importable'
    } else if (view === 'review') {
      f.unreviewed = true
    }
    return f
  }, [filters, view])

  const loadRows = useCallback(async () => {
    setLoading(true)
    setLoadError('')
    try {
      const r = await api.search(effectiveFilters())
      setRows(r.items)
      setTotal(r.total)
    } catch (err) {
      setLoadError(err instanceof Error ? err.message : 'could not load indicators')
    } finally {
      setLoading(false)
    }
  }, [effectiveFilters])

  // Export the current filter set as a CSV download. Unlike the table this is
  // not paginated, and an optional type scope limits it to one class of IOC.
  const exportCsv = useCallback(() => {
    const f: SearchFilters = {
      ...effectiveFilters(),
      format: 'csv',
      limit: EXPORT_LIMIT,
      offset: 0,
    }
    if (exportType) f.ioc_type = EXPORT_TYPES[exportType]
    const path = folder ? `/folders/${folder.id}/iocs` : '/feed'
    window.open(downloadUrl(path, f), '_blank')
  }, [effectiveFilters, exportType, folder])

  useEffect(() => {
    if (!authed) return
    void loadStats()
    void loadFolders()
  }, [authed, loadStats, loadFolders])

  useEffect(() => {
    if (!authed) return
    const t = setTimeout(() => void loadRows(), 250)
    return () => clearTimeout(t)
  }, [authed, loadRows])

  useEffect(() => {
    return onUnauthorized(() => setAuthed(false))
  }, [])

  function clearAllFilters() {
    setQ('')
    setSearch('')
    setView('all')
    setSeverities(new Set())
    setFolder(null)
    setOffset(0)
  }

  function toggleSort(col: string) {
    if (sort === col) setOrder((o) => (o === 'desc' ? 'asc' : 'desc'))
    else {
      setSort(col)
      setOrder('desc')
    }
    setOffset(0)
  }

  function toggleSeverity(s: string) {
    setSeverities((prev) => {
      const next = new Set(prev)
      next.has(s) ? next.delete(s) : next.add(s)
      return next
    })
    setOffset(0)
  }

  function toggleRow(key: string) {
    setSelection((prev) => {
      const next = new Set(prev)
      next.has(key) ? next.delete(key) : next.add(key)
      return next
    })
  }

  function toggleAll(checked: boolean) {
    setSelection((prev) => {
      const next = new Set(prev)
      rows.forEach((r) => (checked ? next.add(rowKey(r)) : next.delete(rowKey(r))))
      return next
    })
  }

  async function deleteSelected() {
    if (!confirm(`Delete ${selection.size} selected IOC(s)? This cannot be undone.`)) return
    const targets = rows.filter((r) => selection.has(rowKey(r)))
    let failed = 0
    for (const t of targets) {
      try {
        await api.deleteIoc(t.ioc_type, t.ioc)
      } catch {
        failed += 1
      }
    }
    setSelection(new Set())
    notify(failed ? `Deleted ${targets.length - failed}, ${failed} failed` : `Deleted ${targets.length}`, failed > 0)
    void loadRows()
    void loadStats()
  }

  async function applyToFolder(folderId: number) {
    const targets = rows.filter((r) => selection.has(rowKey(r)))
    try {
      await api.addFolderIocs(folderId, {
        iocs: targets.map((t) => ({ ioc_type: t.ioc_type, ioc: t.ioc })),
      })
      setSelection(new Set())
      notify(`added ${targets.length} to folder`)
    } catch (err) {
      notify(err instanceof Error ? err.message : 'could not add to folder', true)
    }
  }

  async function signOut() {
    try {
      await api.logout()
    } catch {
      /* already gone */
    }
    setKey('')
    setAuthed(false)
    setPage('iocs')
  }

  // Keyboard: "/" focuses search, Escape closes overlays.
  useEffect(() => {
    function onKey(e: KeyboardEvent) {
      if (e.key === 'Escape') {
        setSelected(null)
        setShowNew(false)
        setShowColumns(false)
        setAuthed((a) => a)
      }
      const tag = (e.target as HTMLElement)?.tagName
      if (e.key === '/' && tag !== 'INPUT' && tag !== 'TEXTAREA') {
        e.preventDefault()
        searchRef.current?.focus()
      }
    }
    document.addEventListener('keydown', onKey)
    return () => document.removeEventListener('keydown', onKey)
  }, [])

  if (!authed) {
    return <Login onSignedIn={() => { setAuthed(true); void loadStats() }} />
  }

  const activeFilters = [
    q && { key: 'q', label: `search: ${q}` },
    view !== 'all' && { key: 'view', label: `view: ${VIEWS[view].title}` },
    severities.size > 0 && { key: 'sev', label: `severity: ${[...severities].join(',')}` },
    folder && { key: 'folder', label: `folder: ${folder.name}` },
  ].filter(Boolean) as { key: string; label: string }[]

  const emptyState =
    !loading && rows.length === 0
      ? activeFilters.length > 0
        ? {
            title: 'Nothing matches the filters currently applied.',
            hint: 'Try broadening the search, clearing a severity filter, or selecting All IOCs.',
          }
        : {
            title: 'No indicators have been collected yet.',
            hint: 'Run a collection cycle to populate the intelligence base.',
          }
      : null

  const viewCounts: Partial<Record<ViewKey, number>> = {
    all: stats?.total,
    critical: stats?.by_severity?.CRITICAL,
    importable: stats?.importable,
    c2: stats?.c2,
    malware: stats?.malware,
    review: stats?.unreviewed,
  }

  return (
    <div className="flex h-[100dvh] flex-col overflow-hidden">
      <header className="flex items-center gap-4 border-b border-line bg-bg2 px-4 py-2.5">
        <div className="flex items-center gap-2 whitespace-nowrap">
          <ShieldCheck size={22} className="text-accent" />
          <span className="text-[14px] font-bold tracking-[0.14em]">IOC&nbsp;INTEL</span>
        </div>

        <div className="relative flex-1">
          <MagnifyingGlass
            size={15}
            className="pointer-events-none absolute left-2.5 top-1/2 -translate-y-1/2 text-faint"
          />
          <input
            ref={searchRef}
            className="ctl w-full pl-8"
            type="search"
            value={search}
            placeholder="Search IOCs, domains, CVEs, malware, actors..."
            onChange={(e) => {
              setSearch(e.target.value)
              setQ(e.target.value)
              setOffset(0)
            }}
            aria-label="Search indicators"
          />
        </div>

        <nav className="flex items-center gap-1.5">
          <Button onClick={() => setShowNew(true)} title="Add an IOC">
            <span className="inline-flex items-center gap-1">
              <Plus size={14} /> IOC
            </span>
          </Button>
          <Button onClick={async () => void api.run()} title="Run a collection cycle now">
            <span className="inline-flex items-center gap-1">
              <Play size={14} /> Run
            </span>
          </Button>
          <Button onClick={() => setPage('folders')} title="Manage threat folders">
            <span className="inline-flex items-center gap-1">
              <ShieldCheck size={14} /> Folders
            </span>
          </Button>
          <Button onClick={() => setPage('api')} title="API keys and integrations">
            <span className="inline-flex items-center gap-1">
              <Key size={14} /> Keys
            </span>
          </Button>
          <Button className="px-2" onClick={signOut} title="Sign out">
            <SignOut size={14} />
          </Button>
        </nav>
      </header>

      <div className="flex items-stretch gap-2 border-b border-line bg-bg1 px-4 py-2">
        {[
          { k: 'total', label: 'Total IOCs', value: stats?.total, cls: 'text-text' },
          { k: 'critical', label: 'Critical', value: stats?.by_severity?.CRITICAL, cls: 'text-crit' },
          { k: 'importable', label: 'Importable', value: stats?.importable, cls: 'text-ok' },
          { k: 'c2', label: 'C2', value: stats?.c2, cls: 'text-accent' },
          { k: 'malware', label: 'Malware', value: stats?.malware, cls: 'text-med' },
        ].map((k) => (
          <div key={k.k} className="flex flex-col px-3">
            <span className={`font-mono text-[15px] font-semibold ${k.cls}`}>{num(k.value)}</span>
            <span className="text-[10.5px] uppercase tracking-[0.07em] text-faint">{k.label}</span>
          </div>
        ))}
        <span className="flex-1" />
        <span className="self-center text-[11.5px] text-faint">
          {stats?.last_cycle
            ? `last cycle #${stats.last_cycle.id} - ${(stats.last_cycle.finished || stats.last_cycle.started || '').slice(0, 16)}`
            : 'no cycle yet'}
        </span>
      </div>

      <div className="flex min-h-0 flex-1">
        <aside className="flex w-[240px] flex-none flex-col overflow-y-auto border-r border-line bg-bg1">
          <div className="px-3 py-2.5">
            <div className="mb-1.5 text-[10.5px] font-semibold uppercase tracking-[0.08em] text-faint">
              Views
            </div>
            {(Object.keys(VIEWS) as ViewKey[])
              .filter((v) => v !== 'review' || (stats?.unreviewed ?? 0) > 0)
              .map((v) => (
                <button
                  key={v}
                  onClick={() => {
                    setView(v)
                    setOffset(0)
                    setFolder(null)
                  }}
                  className={`flex w-full cursor-pointer items-center justify-between rounded-[6px] px-2 py-1.5 text-left text-[12.5px] transition-colors ${
                    view === v ? 'bg-bg4 text-text' : 'text-dim hover:bg-bg3'
                  }`}
                >
                  <span>{VIEWS[v].title}</span>
                  <span className="font-mono text-[11px] text-faint">{num(viewCounts[v])}</span>
                </button>
              ))}
          </div>

          <div className="px-3 py-2.5">
            <div className="mb-1.5 text-[10.5px] font-semibold uppercase tracking-[0.08em] text-faint">
              Severity
            </div>
            <div className="flex flex-wrap gap-1">
              {SEVERITIES.map((s) => (
                <button
                  key={s}
                  onClick={() => toggleSeverity(s)}
                  className={`cursor-pointer rounded-full border px-2 py-0.5 text-[11px] transition-colors ${
                    severities.has(s)
                      ? 'border-accent bg-accent-dim text-accent-ink'
                      : 'border-line2 text-dim hover:border-accent'
                  }`}
                >
                  {s} {num(stats?.by_severity?.[s])}
                </button>
              ))}
            </div>
          </div>

          <div className="min-h-0 flex-1 px-3 py-2.5">
            <div className="mb-1.5 flex items-center justify-between">
              <span className="text-[10.5px] font-semibold uppercase tracking-[0.08em] text-faint">
                Threat Folders
              </span>
              <span className="font-mono text-[11px] text-faint">{num(folders.length)}</span>
            </div>
            <input
              className="ctl mb-2 w-full py-1 text-[12px]"
              type="search"
              placeholder="filter folders..."
              aria-label="Filter folders"
              value={folderSearch}
              onChange={(e) => setFolderSearch(e.target.value)}
            />
            {(() => {
              const q = folderSearch.trim().toLowerCase()
              const filtered = q
                ? folders.filter((f) => f.name.toLowerCase().includes(q))
                : folders
              const autoFolders = filtered.filter((f) => f.kind === 'auto')
              const manualFolders = filtered.filter((f) => f.kind === 'manual')
              return (
                <div className="max-h-[46vh] overflow-y-auto">
                  {autoFolders.length > 0 && (
                    <div className="mb-1.5">
                      <div className="mb-1 flex items-center gap-1.5 px-1">
                        <span className="text-[10px] font-semibold uppercase tracking-[0.07em] text-faint">
                          Auto
                        </span>
                        <span className="font-mono text-[10px] text-faint">{num(autoFolders.length)}</span>
                      </div>
                      {autoFolders.map((f) => (
                        <button
                          key={f.id}
                          onClick={() => {
                            setFolder(folder?.id === f.id ? null : f)
                            setOffset(0)
                          }}
                          className={`flex w-full cursor-pointer items-center justify-between rounded-[6px] px-2 py-1 text-left text-[12px] transition-colors ${
                            folder?.id === f.id ? 'bg-bg4 text-text' : 'text-dim hover:bg-bg3'
                          }`}
                          title={f.description || f.name}
                        >
                          <span className="truncate">{f.name}</span>
                          <span className="font-mono text-[11px] text-faint">{num(f.count)}</span>
                        </button>
                      ))}
                    </div>
                  )}
                  {manualFolders.length > 0 && (
                    <div className="mb-1.5">
                      <div className="mb-1 flex items-center gap-1.5 px-1">
                        <span className="text-[10px] font-semibold uppercase tracking-[0.07em] text-faint">
                          Manual
                        </span>
                        <span className="font-mono text-[10px] text-faint">{num(manualFolders.length)}</span>
                      </div>
                      {manualFolders.map((f) => (
                        <button
                          key={f.id}
                          onClick={() => {
                            setFolder(folder?.id === f.id ? null : f)
                            setOffset(0)
                          }}
                          className={`flex w-full cursor-pointer items-center justify-between rounded-[6px] px-2 py-1 text-left text-[12px] transition-colors ${
                            folder?.id === f.id ? 'bg-bg4 text-text' : 'text-dim hover:bg-bg3'
                          }`}
                          title={f.description || f.name}
                        >
                          <span className="truncate">{f.name}</span>
                          <span className="font-mono text-[11px] text-faint">{num(f.count)}</span>
                        </button>
                      ))}
                    </div>
                  )}
                  {filtered.length === 0 && (
                    <p className="px-2 text-[12px] text-faint">
                      {q ? 'no folders match' : 'no folders yet'}
                    </p>
                  )}
                </div>
              )
            })()}
          </div>
        </aside>

        <main className="min-w-0 flex-1 overflow-y-auto">
          {page === 'folders' ? (
            <div className="p-4">
              <div className="mb-1 text-[12px] text-faint">Intelligence / Threat Folders</div>
              <FolderManager notify={notify} />
            </div>
          ) : page === 'api' ? (
            <div className="p-4">
              <div className="mb-1 text-[12px] text-faint">Intelligence / API and Integrations</div>
              <h1 className="text-[22px] font-semibold">API &amp; Integrations</h1>
              <p className="mb-4 text-dim">
                SIEMs and analysts pull the same feed the bot produces. Authenticate with an API key.
              </p>
              <ApiPage notify={notify} />
              <p className="mt-4 text-[12px] text-faint">
                Full endpoint reference lives in docs/API.md. Push workflow is configured in
                config/push.yaml.
              </p>
            </div>
          ) : (
            <div className="flex h-full flex-col">
              <div className="px-4 pt-3">
                <div className="text-[12px] text-faint">
                  Intelligence /{' '}
                  {folder ? folder.name : VIEWS[view].title}
                </div>
                <div className="flex items-end justify-between gap-4">
                  <div>
                    <h1 className="text-[22px] font-semibold">{folder ? folder.name : VIEWS[view].title}</h1>
                    <p className="text-dim">
                      {folder?.description || VIEWS[view].desc}
                    </p>
                  </div>
                  <div className="flex items-center gap-1.5 pb-1">
                    <Button
                      className="px-2"
                      title="Refresh"
                      onClick={() => {
                        void loadRows()
                        void loadStats()
                        void loadFolders()
                      }}
                    >
                      <ArrowClockwise size={14} />
                    </Button>
                    <div className="relative">
                      <Button onClick={() => setShowColumns((s) => !s)}>
                        <span className="inline-flex items-center gap-1">
                          <Columns size={14} /> Columns
                        </span>
                      </Button>
                      {showColumns && (
                        <div className="absolute right-0 top-full z-50 mt-1 w-44 rounded-ctl border border-line2 bg-bg2 p-1.5 shadow-xl">
                          {COLUMNS.map((c) => (
                            <label key={c.key} className="flex cursor-pointer items-center gap-2 rounded px-2 py-1 text-[12px] hover:bg-bg4">
                              <input
                                type="checkbox"
                                checked={!hiddenColumns.includes(c.key)}
                                onChange={(e) => {
                                  setHiddenColumns((prev) => {
                                    const next = e.target.checked
                                      ? prev.filter((x) => x !== c.key)
                                      : [...prev, c.key]
                                    localStorage.setItem('ioc_hide_cols', JSON.stringify(next))
                                    return next
                                  })
                                }}
                              />
                              {c.label}
                            </label>
                          ))}
                        </div>
                      )}
                    </div>
                    <select
                      className="ctl py-1 text-[12px]"
                      value={exportType}
                      onChange={(e) => setExportType(e.target.value)}
                      aria-label="Export IOC types"
                      title="Which IOC types the CSV export includes"
                    >
                      <option value="">All types</option>
                      <option value="ip">IPs only</option>
                      <option value="hash">Hashes only</option>
                      <option value="domain">Domains only</option>
                      <option value="url">URLs only</option>
                    </select>
                    <Button
                      onClick={exportCsv}
                      title="Export the current filters as CSV"
                    >
                      Export CSV
                    </Button>
                  </div>
                </div>
              </div>

              <div className="mt-3 flex items-center gap-2 border-y border-line px-4 py-2">
                {activeFilters.map((f) => (
                  <button
                    key={f.key}
                    onClick={() => {
                      if (f.key === 'q') {
                        setQ('')
                        setSearch('')
                      }
                      if (f.key === 'view') setView('all')
                      if (f.key === 'sev') setSeverities(new Set())
                      if (f.key === 'folder') setFolder(null)
                      setOffset(0)
                    }}
                    className="cursor-pointer rounded-full border border-accent bg-accent-dim px-2.5 py-0.5 text-[11.5px] text-accent-ink transition-colors hover:bg-bg4"
                    title="Remove this filter"
                  >
                    {f.label} x
                  </button>
                ))}
                {activeFilters.length > 1 && (
                  <button
                    onClick={clearAllFilters}
                    className="cursor-pointer rounded-full border border-dashed border-line2 px-2.5 py-0.5 text-[11.5px] text-dim transition-colors hover:border-accent hover:text-text"
                  >
                    clear all x
                  </button>
                )}
                <span className="flex-1" />
                <span className="text-[12px] text-dim">{num(total)} matching</span>
                <select
                  className="ctl py-1 text-[12px]"
                  value={limit}
                  onChange={(e) => {
                    setLimit(Number(e.target.value))
                    setOffset(0)
                  }}
                  aria-label="Page size"
                >
                  {PAGE_SIZES.map((n) => (
                    <option key={n} value={n}>
                      {n}
                    </option>
                  ))}
                </select>
              </div>

              <div className="min-h-0 flex-1 overflow-hidden">
                {loadError ? (
                  <div className="p-6">
                    <ErrorText>{loadError}</ErrorText>
                  </div>
                ) : (
                  <IocTable
                    rows={rows}
                    loading={loading}
                    total={total}
                    offset={offset}
                    limit={limit}
                    sort={sort}
                    order={order}
                    hiddenColumns={hiddenColumns}
                    selection={selection}
                    folderOptions={folders.map((f) => ({ id: f.id, name: f.name }))}
                    empty={emptyState}
                    onSort={toggleSort}
                    onPage={setOffset}
                    onOpen={setSelected}
                    onToggleRow={toggleRow}
                    onToggleAll={toggleAll}
                    onClearFilters={clearAllFilters}
                    onApplyToFolder={applyToFolder}
                    onDeleteSelected={deleteSelected}
                  />
                )}
              </div>
            </div>
          )}
        </main>
      </div>

      {selected && (
        <Drawer
          ioc={selected}
          onClose={() => setSelected(null)}
          onSaved={() => {
            setSelected(null)
            void loadRows()
          }}
          onDeleted={() => {
            setSelected(null)
            void loadRows()
            void loadStats()
          }}
          notify={notify}
        />
      )}

      {showNew && (
        <NewIocModal
          onClose={() => setShowNew(false)}
          onCreated={() => {
            setShowNew(false)
            void loadRows()
            void loadStats()
          }}
          notify={notify}
        />
      )}

      {notice && <Toast message={notice.message} error={notice.error} />}
    </div>
  )
}