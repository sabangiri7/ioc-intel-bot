import { useEffect, useState } from 'react'
import { api, type Ioc } from '../../lib/api'
import { Button, ErrorText, Modal, SeverityBadge } from '../../lib/ui'

const IOC_TYPES = [
  'IPv4', 'IPv6', 'Domain', 'URL', 'SHA256', 'SHA1', 'MD5', 'Email',
  'File-Name', 'CVE', 'Malware', 'Threat-Actor', 'Campaign',
]

export default function Drawer({
  ioc,
  onClose,
  onSaved,
  onDeleted,
  notify,
}: {
  ioc: Ioc
  onClose: () => void
  onSaved: () => void
  onDeleted: () => void
  notify: (message: string, error?: boolean) => void
}) {
  const [item, setItem] = useState<Ioc>(ioc)
  const [saving, setSaving] = useState(false)
  const [error, setError] = useState('')
  const [folders, setFolders] = useState<{ id: number; name: string }[]>([])
  const [folderChoice, setFolderChoice] = useState('')

  useEffect(() => {
    setItem(ioc)
    setError('')
    void api
      .getIoc(ioc.ioc_type, ioc.ioc)
      .then(setItem)
      .catch(() => {
        /* fall back to the row we already have */
      })
    void api
      .folders(true)
      .then((r) => setFolders(r.items))
      .catch(() => setFolders([]))
  }, [ioc])

  async function save() {
    setSaving(true)
    setError('')
    try {
      await api.updateIoc(item.ioc_type, item.ioc, {
        severity: item.severity,
        confidence: item.confidence,
        categories: item.categories ?? [],
        malware_family: item.malware_family,
        threat_actor: item.threat_actor,
        campaign: item.campaign,
        description: item.description,
        tags: item.tags ?? [],
      })
      notify('IOC updated')
      onSaved()
    } catch (err) {
      setError(err instanceof Error ? err.message : 'save failed')
    } finally {
      setSaving(false)
    }
  }

  async function remove() {
    if (!confirm(`Delete ${item.ioc_type} ${item.ioc}?`)) return
    try {
      await api.deleteIoc(item.ioc_type, item.ioc)
      notify('IOC deleted')
      onDeleted()
    } catch (err) {
      setError(err instanceof Error ? err.message : 'delete failed')
    }
  }

  async function addToFolder() {
    if (!folderChoice) return
    try {
      await api.addFolderIocs(Number(folderChoice), {
        iocs: [{ ioc_type: item.ioc_type, ioc: item.ioc }],
      })
      notify('added to folder')
      setFolderChoice('')
      onSaved()
    } catch (err) {
      setError(err instanceof Error ? err.message : 'could not add to folder')
    }
  }

  const patch = (p: Partial<Ioc>) => setItem((s) => ({ ...s, ...p }))

  return (
    <div className="fixed inset-0 z-[65] flex justify-end" role="presentation" onClick={onClose}>
      <aside
        className="flex h-full w-full max-w-[460px] flex-col border-l border-line2 bg-bg2 shadow-xl"
        onClick={(e) => e.stopPropagation()}
        role="dialog"
        aria-modal="true"
        aria-label={`Details for ${item.ioc}`}
      >
        <header className="flex items-center gap-2 border-b border-line2 px-4 py-2.5">
          <span className="font-mono text-[12px] text-dim">{item.ioc_type}</span>
          <span className="flex-1" />
          <Button className="px-2 py-1" onClick={onClose} aria-label="Close details">
            Close
          </Button>
        </header>

        <div className="flex-1 overflow-y-auto px-4 py-3">
          <div className="mb-3">
            <div className="label">Value</div>
            <div className="font-mono text-[12.5px] break-all">{item.ioc}</div>
          </div>

          <div className="mb-3 grid grid-cols-2 gap-2">
            <div>
              <label className="label" htmlFor="d-sev">
                Severity
              </label>
              <select
                id="d-sev"
                className="ctl mt-1"
                value={item.severity}
                onChange={(e) => patch({ severity: e.target.value as Ioc['severity'] })}
              >
                {['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].map((s) => (
                  <option key={s}>{s}</option>
                ))}
              </select>
            </div>
            <div>
              <label className="label" htmlFor="d-conf">
                Confidence
              </label>
              <select
                id="d-conf"
                className="ctl mt-1"
                value={item.confidence}
                onChange={(e) => patch({ confidence: e.target.value as Ioc['confidence'] })}
              >
                {['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].map((s) => (
                  <option key={s}>{s}</option>
                ))}
              </select>
            </div>
          </div>

          <div className="mb-3 flex items-center gap-2">
            <span className="label">Validation</span>
            <SeverityBadge value={item.validation_status} />
          </div>

          <Field label="Categories (semicolon separated)">
            <input
              className="ctl"
              value={(item.categories ?? []).join(';')}
              onChange={(e) => patch({ categories: e.target.value.split(';').filter(Boolean) })}
            />
          </Field>

          <div className="mb-3 grid grid-cols-2 gap-2">
            <Field label="Malware family">
              <input
                className="ctl"
                value={item.malware_family ?? ''}
                onChange={(e) => patch({ malware_family: e.target.value })}
              />
            </Field>
            <Field label="Threat actor">
              <input
                className="ctl"
                value={item.threat_actor ?? ''}
                onChange={(e) => patch({ threat_actor: e.target.value })}
              />
            </Field>
          </div>

          <Field label="Campaign">
            <input
              className="ctl"
              value={item.campaign ?? ''}
              onChange={(e) => patch({ campaign: e.target.value })}
            />
          </Field>

          <Field label="Description">
            <textarea
              className="ctl"
              rows={3}
              value={item.description ?? ''}
              onChange={(e) => patch({ description: e.target.value })}
            />
          </Field>

          <Field label="Tags (semicolon separated)">
            <input
              className="ctl"
              value={(item.tags ?? []).join(';')}
              onChange={(e) => patch({ tags: e.target.value.split(';').filter(Boolean) })}
            />
          </Field>

          <div className="mb-3 flex gap-4 text-[12px] text-dim">
            <span>
              first: <span className="font-mono">{item.first_seen || '-'}</span>
            </span>
            <span>
              last: <span className="font-mono">{item.last_seen || '-'}</span>
            </span>
            <span>
              importable: <span className="font-mono">{item.crowdstrike_importable}</span>
            </span>
          </div>

          <div className="mb-3">
            <div className="label mb-1">Folders</div>
            <div className="flex flex-wrap gap-1">
              {(item.folders ?? []).length === 0 && <span className="text-faint">none</span>}
              {(item.folders ?? []).map((f) => (
                <span key={f} className="rounded-[4px] bg-bg4 px-1.5 py-0.5 text-[11px] text-dim">
                  {f}
                </span>
              ))}
            </div>
            <div className="mt-2 flex gap-2">
              <select
                className="ctl"
                value={folderChoice}
                onChange={(e) => setFolderChoice(e.target.value)}
                aria-label="Add to folder"
              >
                <option value="">Add to folder...</option>
                {folders.map((f) => (
                  <option key={f.id} value={f.id}>
                    {f.name}
                  </option>
                ))}
              </select>
              <Button onClick={addToFolder} disabled={!folderChoice}>
                Add
              </Button>
            </div>
          </div>

          <div className="mb-3">
            <div className="label mb-1">Sources</div>
            <div className="font-mono text-[11.5px] break-all text-dim">
              {(item.sources ?? []).join(', ') || '-'}
            </div>
          </div>

          <ErrorText>{error}</ErrorText>
        </div>

        <footer className="flex items-center gap-2 border-t border-line2 px-4 py-2.5">
          <Button variant="danger" onClick={remove}>
            Delete
          </Button>
          <span className="flex-1" />
          <Button variant="primary" onClick={save} disabled={saving}>
            {saving ? 'Saving...' : 'Save changes'}
          </Button>
        </footer>
      </aside>
    </div>
  )
}

function Field({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div className="mb-3">
      <div className="label mb-1">{label}</div>
      {children}
    </div>
  )
}

export function NewIocModal({
  onClose,
  onCreated,
  notify,
}: {
  onClose: () => void
  onCreated: () => void
  notify: (m: string, e?: boolean) => void
}) {
  const [value, setValue] = useState('')
  const [type, setType] = useState('IPv4')
  const [severity, setSeverity] = useState('MEDIUM')
  const [confidence, setConfidence] = useState('MEDIUM')
  const [categories, setCategories] = useState('')
  const [family, setFamily] = useState('')
  const [error, setError] = useState('')
  const [busy, setBusy] = useState(false)

  async function create() {
    setBusy(true)
    setError('')
    try {
      await api.createIoc({
        ioc: value.trim(),
        ioc_type: type,
        severity: severity as Ioc['severity'],
        confidence: confidence as Ioc['confidence'],
        categories: categories.split(';').map((c) => c.trim()).filter(Boolean),
        malware_family: family,
      })
      notify('IOC created')
      onCreated()
    } catch (err) {
      setError(err instanceof Error ? err.message : 'create failed')
    } finally {
      setBusy(false)
    }
  }

  return (
    <Modal title="Add IOC" onClose={onClose}>
      <div className="grid grid-cols-[1fr_auto] gap-2">
        <div>
          <label className="label" htmlFor="n-ioc">
            Value
          </label>
          <input
            id="n-ioc"
            className="ctl mt-1"
            value={value}
            onChange={(e) => setValue(e.target.value)}
            placeholder="1.2.3.4 / evil.example / sha256..."
          />
        </div>
        <div>
          <label className="label" htmlFor="n-type">
            Type
          </label>
          <select
            id="n-type"
            className="ctl mt-1"
            value={type}
            onChange={(e) => setType(e.target.value)}
          >
            {IOC_TYPES.map((t) => (
              <option key={t}>{t}</option>
            ))}
          </select>
        </div>
      </div>

      <div className="grid grid-cols-2 gap-2">
        <div>
          <label className="label" htmlFor="n-sev">
            Severity
          </label>
          <select
            id="n-sev"
            className="ctl mt-1"
            value={severity}
            onChange={(e) => setSeverity(e.target.value)}
          >
            {['HIGH', 'CRITICAL', 'MEDIUM', 'LOW'].map((s) => (
              <option key={s}>{s}</option>
            ))}
          </select>
        </div>
        <div>
          <label className="label" htmlFor="n-conf">
            Confidence
          </label>
          <select
            id="n-conf"
            className="ctl mt-1"
            value={confidence}
            onChange={(e) => setConfidence(e.target.value)}
          >
            {['HIGH', 'MEDIUM', 'CRITICAL', 'LOW'].map((s) => (
              <option key={s}>{s}</option>
            ))}
          </select>
        </div>
      </div>

      <div>
        <label className="label" htmlFor="n-cat">
          Categories
        </label>
        <input
          id="n-cat"
          className="ctl mt-1"
          value={categories}
          onChange={(e) => setCategories(e.target.value)}
          placeholder="C2; MALWARE"
        />
      </div>

      <div>
        <label className="label" htmlFor="n-fam">
          Malware family
        </label>
        <input id="n-fam" className="ctl mt-1" value={family} onChange={(e) => setFamily(e.target.value)} />
      </div>

      <ErrorText>{error}</ErrorText>

      <div className="mt-2 flex gap-2">
        <Button onClick={onClose}>Cancel</Button>
        <span className="flex-1" />
        <Button variant="primary" onClick={create} disabled={busy || !value.trim()}>
          {busy ? 'Creating...' : 'Create'}
        </Button>
      </div>
    </Modal>
  )
}