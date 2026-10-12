import { useEffect, useState } from 'react'
import { api, type Folder } from '../lib/api'
import { Button, ErrorText, num } from '../lib/ui'

const AUTO_GROUP_LABELS: Record<string, string> = {
  malware: 'Malware Families',
  actor: 'Threat Actors',
}

export default function FolderManager({ notify }: { notify: (m: string, e?: boolean) => void }) {
  const [folders, setFolders] = useState<Folder[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')

  const [showCreate, setShowCreate] = useState(false)
  const [newName, setNewName] = useState('')
  const [newDesc, setNewDesc] = useState('')
  const [creating, setCreating] = useState(false)
  const [createError, setCreateError] = useState('')

  const [editing, setEditing] = useState<Folder | null>(null)
  const [editName, setEditName] = useState('')
  const [editDesc, setEditDesc] = useState('')
  const [saving, setSaving] = useState(false)

  async function load() {
    setLoading(true)
    setError('')
    try {
      const r = await api.folders(false)
      setFolders(r.items)
    } catch (err) {
      setError(err instanceof Error ? err.message : 'failed to load folders')
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => { void load() }, [])

  async function createFolder() {
    setCreating(true)
    setCreateError('')
    try {
      await api.createFolder({ name: newName.trim(), description: newDesc.trim() })
      setNewName('')
      setNewDesc('')
      setShowCreate(false)
      notify('folder created')
      void load()
    } catch (err) {
      setCreateError(err instanceof Error ? err.message : 'could not create folder')
    } finally {
      setCreating(false)
    }
  }

  async function startEdit(f: Folder) {
    setEditing(f)
    setEditName(f.name)
    setEditDesc(f.description || '')
  }

  async function saveEdit() {
    if (!editing) return
    setSaving(true)
    try {
      await api.updateFolder(editing.id, { name: editName.trim(), description: editDesc.trim() })
      setEditing(null)
      notify('folder updated')
      void load()
    } catch (err) {
      setError(err instanceof Error ? err.message : 'could not save folder')
    } finally {
      setSaving(false)
    }
  }

  async function deleteFolder(f: Folder) {
    if (f.kind === 'auto') return
    if (!confirm(`Delete "${f.name}"? This cannot be undone.`)) return
    try {
      await api.deleteFolder(f.id)
      notify('folder deleted')
      void load()
    } catch (err) {
      setError(err instanceof Error ? err.message : 'could not delete folder')
    }
  }

  const autoFolders = folders.filter((f) => f.kind === 'auto')
  const manualFolders = folders.filter((f) => f.kind === 'manual')

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-[16px] font-semibold">Threat Folders</h2>
          <p className="mt-0.5 text-[12px] text-dim">
            {num(folders.length)} folders total — {num(autoFolders.length)} auto-generated,{' '}
            {num(manualFolders.length)} manually curated
          </p>
        </div>
        <Button onClick={() => setShowCreate(true)} title="Create a new manual folder">
          + New Folder
        </Button>
      </div>

      <ErrorText>{error}</ErrorText>

      {loading && (
        <div className="rounded-ctl border border-line bg-bg2 p-3 text-[13px] text-dim">
          Loading folders...
        </div>
      )}

      {!loading && folders.length === 0 && (
        <div className="rounded-ctl border border-dashed border-line2 bg-bg2 p-6 text-center">
          <p className="text-[13px] text-dim">No folders yet.</p>
          <p className="mt-1 text-[12px] text-faint">
            Auto folders are created during collection. Create a manual folder to group IOCs by campaign,
            operation, or any custom grouping.
          </p>
        </div>
      )}

      {autoFolders.length > 0 && (
        <section>
          <h3 className="mb-2 text-[11px] font-semibold uppercase tracking-[0.08em] text-faint">
            Auto-Generated
          </h3>
          <div className="space-y-1.5">
            {autoFolders.map((f) => (
              <div
                key={f.id}
                className="flex items-center gap-3 rounded-ctl border border-line bg-bg2 px-3 py-2"
              >
                <span className="text-[10px] font-semibold uppercase tracking-[0.07em] text-faint">
                  AUTO
                </span>
                <div className="flex-1 min-w-0">
                  <div className="font-mono text-[13px] text-text">{f.name}</div>
                  {f.description && (
                    <div className="text-[11px] text-faint">{f.description}</div>
                  )}
                </div>
                <span className="font-mono text-[12px] text-dim">{num(f.count)} IOCs</span>
                <span className="text-[10px] text-faint">
                  ({AUTO_GROUP_LABELS[f.group] ?? f.group})
                </span>
              </div>
            ))}
          </div>
        </section>
      )}

      {manualFolders.length > 0 && (
        <section>
          <h3 className="mb-2 text-[11px] font-semibold uppercase tracking-[0.08em] text-faint">
            Manual
          </h3>
          <div className="space-y-1.5">
            {manualFolders.map((f) => (
              <div
                key={f.id}
                className="rounded-ctl border border-line bg-bg2 px-3 py-2"
              >
                {editing?.id === f.id ? (
                  <div className="space-y-2">
                    <div>
                      <label className="label mb-0.5">Name</label>
                      <input
                        className="ctl w-full"
                        value={editName}
                        onChange={(e) => setEditName(e.target.value)}
                        autoFocus
                      />
                    </div>
                    <div>
                      <label className="label mb-0.5">Description</label>
                      <input
                        className="ctl w-full"
                        value={editDesc}
                        onChange={(e) => setEditDesc(e.target.value)}
                        placeholder="Optional description..."
                      />
                    </div>
                    <div className="flex gap-2">
                      <Button size="sm" onClick={saveEdit} disabled={saving}>
                        {saving ? 'Saving...' : 'Save'}
                      </Button>
                      <Button
                        size="sm"
                        variant="ghost"
                        onClick={() => setEditing(null)}
                      >
                        Cancel
                      </Button>
                    </div>
                  </div>
                ) : (
                  <div className="flex items-center gap-3">
                    <div className="flex-1 min-w-0">
                      <div className="font-mono text-[13px] text-text">{f.name}</div>
                      {f.description && (
                        <div className="text-[11px] text-faint">{f.description}</div>
                      )}
                    </div>
                    <span className="font-mono text-[12px] text-dim">{num(f.count)} IOCs</span>
                    <Button
                      size="sm"
                      variant="ghost"
                      className="py-0.5 text-[11.5px]"
                      onClick={() => startEdit(f)}
                    >
                      Edit
                    </Button>
                    <Button
                      size="sm"
                      variant="ghost"
                      className="py-0.5 text-[11.5px] text-danger"
                      onClick={() => deleteFolder(f)}
                    >
                      Delete
                    </Button>
                  </div>
                )}
              </div>
            ))}
          </div>
        </section>
      )}

      {showCreate && (
        <div className="rounded-ctl border border-accent bg-bg2 p-4">
          <h4 className="mb-3 text-[13px] font-semibold">Create Manual Folder</h4>
          <div className="space-y-2">
            <div>
              <label className="label">Name *</label>
              <input
                className="ctl w-full"
                value={newName}
                onChange={(e) => setNewName(e.target.value)}
                placeholder="e.g., Operation Nightfall"
                autoFocus
              />
            </div>
            <div>
              <label className="label">Description</label>
              <input
                className="ctl w-full"
                value={newDesc}
                onChange={(e) => setNewDesc(e.target.value)}
                placeholder="Optional description..."
              />
            </div>
          </div>
          <ErrorText>{createError}</ErrorText>
          <div className="mt-3 flex gap-2">
            <Button variant="primary" size="sm" onClick={createFolder} disabled={creating || !newName.trim()}>
              {creating ? 'Creating...' : 'Create'}
            </Button>
            <Button size="sm" variant="ghost" onClick={() => { setShowCreate(false); setCreateError('') }}>
              Cancel
            </Button>
          </div>
        </div>
      )}
    </div>
  )
}
