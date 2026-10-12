import { useState } from 'react'
import { Folder as FolderIcon, FolderOpen, ChevronRight } from 'lucide-react'
import { type Folder } from '../lib/api'
import { num } from '../lib/ui'

const AUTO_GROUP_COLORS: Record<string, string> = {
  malware: 'border-l-high text-high',
  actor: 'border-l-accent text-accent',
}

const MANUAL_GROUP_COLOR = 'border-l-ok text-ok'

function FolderItem({
  f,
  isActive,
  onSelect,
}: {
  f: Folder
  isActive: boolean
  onSelect: (f: Folder) => void
}) {
  const isAuto = f.kind === 'auto'
  const groupColor = isAuto
    ? AUTO_GROUP_COLORS[f.group ?? 'malware'] ?? AUTO_GROUP_COLORS.malware
    : MANUAL_GROUP_COLOR

  return (
    <button
      onClick={() => onSelect(f)}
      className={`flex w-full cursor-pointer items-center gap-2 rounded-[5px] border-l-2 border-l-transparent pl-2 py-1.5 text-left text-[12px] transition-colors ${
        isActive
          ? `${groupColor} bg-bg4 font-medium`
          : 'text-dim hover:bg-bg3 hover:border-l-2'
      }`}
      title={f.description || f.name}
      aria-pressed={isActive}
    >
      <ChevronRight
        size={10}
        className={`shrink-0 transition-transform duration-150 ${isActive ? 'text-faint' : 'text-faint opacity-0'}`}
      />
      <span className="min-w-0 flex-1 truncate font-mono">{f.name}</span>
      <span className="shrink-0 font-mono text-[11px] text-faint">{num(f.count)}</span>
    </button>
  )
}

function CollapsibleSection({
  title,
  icon,
  count,
  defaultOpen = true,
  children,
}: {
  title: string
  icon: React.ReactNode
  count: number
  defaultOpen?: boolean
  children: React.ReactNode
}) {
  const [open, setOpen] = useState(defaultOpen)

  return (
    <div className="mb-1.5">
      <button
        onClick={() => setOpen((o) => !o)}
        className="flex w-full cursor-pointer items-center gap-1.5 rounded-[5px] px-2 py-1 text-left transition-colors hover:bg-bg3"
        aria-expanded={open}
      >
        <span className={`text-[10px] font-semibold uppercase tracking-[0.07em] ${open ? 'text-fg-subtle' : 'text-faint'}`}>
          {icon}
          {title}
        </span>
        <span className="ml-auto font-mono text-[10.5px] text-faint">{num(count)}</span>
        <ChevronRight
          size={12}
          className={`text-faint transition-transform duration-150 ease-out ${open ? 'rotate-90' : ''}`}
        />
      </button>
      <div
        className={`overflow-hidden transition-all duration-200 ease-out ${
          open ? 'max-h-[400px] opacity-100' : 'max-h-0 opacity-0'
        }`}
      >
        <div className="mt-0.5 space-y-0.5 pb-1">{children}</div>
      </div>
    </div>
  )
}

export default function FolderNav({
  folders,
  activeFolder,
  onSelectFolder,
}: {
  folders: Folder[]
  activeFolder: Folder | null
  onSelectFolder: (f: Folder | null) => void
}) {
  const [search, setSearch] = useState('')

  const q = search.trim().toLowerCase()
  const filtered = q
    ? folders.filter(
        (f) =>
          f.name.toLowerCase().includes(q) ||
          (f.description ?? '').toLowerCase().includes(q),
      )
    : folders

  const autoFolders = filtered.filter((f) => f.kind === 'auto')
  const manualFolders = filtered.filter((f) => f.kind === 'manual')

  const handleSelect = (f: Folder) => {
    if (activeFolder?.id === f.id) {
      onSelectFolder(null)
    } else {
      onSelectFolder(f)
    }
  }

  return (
    <div className="flex flex-col gap-0.5">
      <input
        className="ctl mb-1.5 w-full py-1 text-[12px]"
        type="search"
        placeholder="filter folders..."
        aria-label="Filter folders"
        value={search}
        onChange={(e) => setSearch(e.target.value)}
      />

      {!autoFolders.length && !manualFolders.length && (
        <p className="px-2 py-1 text-[11.5px] text-faint">
          {q ? 'no folders match' : 'no folders yet'}
        </p>
      )}

      {autoFolders.length > 0 && (
        <CollapsibleSection
          title="Auto-generated"
          icon={<FolderOpen size={12} />}
          count={autoFolders.length}
        >
          {autoFolders.map((f) => (
            <FolderItem
              key={f.id}
              f={f}
              isActive={activeFolder?.id === f.id}
              onSelect={handleSelect}
            />
          ))}
        </CollapsibleSection>
      )}

      {manualFolders.length > 0 && (
        <CollapsibleSection
          title="Manual"
          icon={<FolderIcon size={12} />}
          count={manualFolders.length}
        >
          {manualFolders.map((f) => (
            <FolderItem
              key={f.id}
              f={f}
              isActive={activeFolder?.id === f.id}
              onSelect={handleSelect}
            />
          ))}
        </CollapsibleSection>
      )}
    </div>
  )
}
