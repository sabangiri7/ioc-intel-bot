import { useMemo, useState } from 'react'
import type { Ioc, Severity } from '../lib/api'
import { Button, ConfidenceBar, EmptyState, SeverityBadge, Skeleton, TypeTag } from '../lib/ui'

export interface ColumnKey {
  key: string
  label: string
  sortable?: string
}

export const COLUMNS: ColumnKey[] = [
  { key: 'ioc', label: 'IOC', sortable: 'ioc' },
  { key: 'ioc_type', label: 'Type' },
  { key: 'severity', label: 'Severity', sortable: 'severity' },
  { key: 'confidence', label: 'Confidence', sortable: 'confidence' },
  { key: 'category', label: 'Category' },
  { key: 'malware', label: 'Malware / Actor', sortable: 'malware_family' },
  { key: 'folders', label: 'Folders' },
  { key: 'last_seen', label: 'Last seen', sortable: 'last_seen' },
]

export default function IocTable({
  rows,
  loading,
  total,
  offset,
  limit,
  sort,
  order,
  hiddenColumns,
  selection,
  folderOptions,
  empty,
  onSort,
  onPage,
  onOpen,
  onToggleRow,
  onToggleAll,
  onClearFilters,
  onApplyToFolder,
  onDeleteSelected,
}: {
  rows: Ioc[]
  loading: boolean
  total: number
  offset: number
  limit: number
  sort: string
  order: 'asc' | 'desc'
  hiddenColumns: string[]
  selection: Set<string>
  folderOptions: { id: number; name: string }[]
  empty: { title: string; hint: string } | null
  onSort: (col: string) => void
  onPage: (nextOffset: number) => void
  onOpen: (row: Ioc) => void
  onToggleRow: (key: string) => void
  onToggleAll: (checked: boolean) => void
  onClearFilters: () => void
  onApplyToFolder: (folderId: number) => void
  onDeleteSelected: () => void
}) {
  const [folderChoice, setFolderChoice] = useState('')
  const visible = useMemo(
    () => COLUMNS.filter((c) => !hiddenColumns.includes(c.key)),
    [hiddenColumns],
  )

  if (loading) {
    return (
      <table className="w-full border-collapse text-[13px]">
        <tbody>
          {Array.from({ length: 8 }).map((_, i) => (
            <tr key={i} className="border-b border-line">
              <td className="px-3 py-2">
                <Skeleton className="h-2.5 w-[70%]" />
              </td>
              <td className="px-3 py-2">
                <Skeleton className="h-2.5 w-12" />
              </td>
              <td className="px-3 py-2">
                <Skeleton className="h-2.5 w-16" />
              </td>
              <td className="px-3 py-2">
                <Skeleton className="h-2.5 w-24" />
              </td>
              <td className="px-3 py-2">
                <Skeleton className="h-2.5 w-32" />
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    )
  }

  if (rows.length === 0 && empty === null) {
    return (
      <EmptyState
        title="No indicators have been collected yet."
        hint="Run a collection cycle to populate the intelligence base."
        action={
          <Button onClick={onClearFilters} className="mt-2">
            Clear all filters
          </Button>
        }
      />
    )
  }

  if (empty) {
    return (
      <EmptyState
        title={empty.title}
        hint={empty.hint}
        action={
          <Button onClick={onClearFilters} className="mt-2">
            Clear all filters
          </Button>
        }
      />
    )
  }

  const allSelected = rows.length > 0 && rows.every((r) => selection.has(rowKey(r)))
  const from = total ? offset + 1 : 0
  const to = Math.min(offset + limit, total)

  return (
    <div className="flex h-full flex-col">
      {selection.size > 0 && (
        <div className="flex items-center gap-2 border-b border-line bg-bg2 px-3 py-2">
          <b className="text-[12.5px]">{selection.size} selected</b>
          <select
            className="ctl py-1 text-[12px]"
            value={folderChoice}
            onChange={(e) => setFolderChoice(e.target.value)}
            aria-label="Add selected to folder"
          >
            <option value="">Add to folder...</option>
            {folderOptions.map((f: { id: number; name: string }) => (
              <option key={f.id} value={f.id}>
                {f.name}
              </option>
            ))}
          </select>
          <Button
            className="py-1 text-[11.5px]"
            disabled={!folderChoice}
            onClick={() => {
              onApplyToFolder(Number(folderChoice))
              setFolderChoice('')
            }}
          >
            Apply
          </Button>
          <Button variant="danger" className="py-1 text-[11.5px]" onClick={onDeleteSelected}>
            Delete
          </Button>
          <span className="flex-1" />
          <Button
            className="py-1 text-[11.5px]"
            onClick={() => {
              selection.clear()
              onToggleAll(false)
            }}
          >
            Clear
          </Button>
        </div>
      )}

      <div className="min-h-0 flex-1 overflow-auto">
        <table className="w-full border-collapse text-[13px]">
          <thead className="sticky top-0 z-10 bg-bg2">
            <tr>
              <th className="w-8 px-3 py-2">
                <input
                  type="checkbox"
                  checked={allSelected}
                  ref={(el) => {
                    if (el) el.indeterminate = !allSelected && selection.size > 0
                  }}
                  onChange={(e) => onToggleAll(e.target.checked)}
                  aria-label="Select all on this page"
                />
              </th>
              {visible.map((c) => (
                <th
                  key={c.key}
                  className="px-3 py-2 text-left text-[10px] uppercase tracking-[0.07em] text-faint"
                >
                  {c.sortable ? (
                    <button
                      type="button"
                      onClick={() => onSort(c.sortable!)}
                      className="cursor-pointer uppercase tracking-[0.07em] hover:text-accent"
                    >
                      {c.label}
                      {sort === c.sortable && (
                        <span className="ml-1 text-accent">{order === 'desc' ? '▾' : '▴'}</span>
                      )}
                    </button>
                  ) : (
                    c.label
                  )}
                </th>
              ))}
              <th className="w-8 px-3 py-2" />
            </tr>
          </thead>
          <tbody>
            {rows.map((row) => {
              const key = rowKey(row)
              const checked = selection.has(key)
              return (
                <tr
                  key={key}
                  onClick={() => onOpen(row)}
                  className="cursor-pointer border-b border-line hover:bg-bg1"
                  aria-selected={checked}
                >
                  <td className="px-3 py-2" onClick={(e) => e.stopPropagation()}>
                    <input
                      type="checkbox"
                      checked={checked}
                      onChange={() => onToggleRow(key)}
                      aria-label={`Select ${row.ioc}`}
                    />
                  </td>
                  {visible.map((c) => (
                    <td key={c.key} className="px-3 py-2 align-middle">
                      {renderCell(c.key, row)}
                    </td>
                  ))}
                  <td className="px-3 py-2 text-right text-faint">...</td>
                </tr>
              )
            })}
          </tbody>
        </table>
      </div>

      <div className="flex items-center justify-end gap-3 px-3 py-2.5">
        <span className="text-[12px] text-dim">
          {from}-{to} of {total.toLocaleString()}
        </span>
        <Button disabled={offset === 0} onClick={() => onPage(Math.max(0, offset - limit))}>
          Prev
        </Button>
        <Button disabled={to >= total} onClick={() => onPage(offset + limit)}>
          Next
        </Button>
      </div>

    </div>
  )
}

export function rowKey(r: Ioc): string {
  return `${r.ioc_type}|${r.ioc}`
}

function renderCell(key: string, r: Ioc) {
  switch (key) {
    case 'ioc':
      return <span className="font-mono text-[12px] break-all">{r.ioc}</span>
    case 'ioc_type':
      return <TypeTag value={r.ioc_type} />
    case 'severity':
      return <SeverityBadge value={r.severity} />
    case 'confidence':
      return <ConfidenceBar value={r.confidence} />
    case 'category':
      return (
        <span className="flex flex-wrap gap-1">
          {(r.categories ?? []).slice(0, 3).map((c) => (
            <span key={c} className="rounded-[4px] bg-bg4 px-1.5 py-0.5 text-[10.5px] text-dim">
              {c}
            </span>
          ))}
        </span>
      )
    case 'malware': {
      const label = r.malware_family || r.threat_actor
      return label ? (
        <span className="rounded-[4px] border border-line2 px-1.5 py-0.5 text-[11px] text-dim">
          {label}
        </span>
      ) : (
        <span className="text-faint">-</span>
      )
    }
    case 'folders':
      return r.folders?.length ? (
        <span className="text-[11.5px] text-dim">{r.folders.slice(0, 2).join(', ')}</span>
      ) : (
        <span className="text-faint">-</span>
      )
    case 'last_seen':
      return <span className="whitespace-nowrap font-mono text-[11.5px] text-dim">{r.last_seen || '-'}</span>
    default:
      return null
  }
}

export const SEVERITIES: Severity[] = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']