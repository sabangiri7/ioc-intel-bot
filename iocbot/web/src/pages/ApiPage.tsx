import { useEffect, useState } from 'react'
import { Copy } from 'lucide-react'
import {
  api,
  getKey,
  type ApiKey,
  type DashboardUser,
  type Role,
  type RoleInfo,
} from '../lib/api'
import { Button, ErrorText, num } from '../lib/ui'

const PLATFORMS = ['Splunk', 'Elastic', 'Wazuh', 'FortiSIEM', 'CrowdStrike', 'QRadar', 'Sentinel', 'Other']

const PLATFORM_HINTS: Record<string, string> = {
  Splunk: 'Scripted input or a scheduled search that curls the CSV feed.',
  Elastic: 'Logstash http_poller or Elastic Agent against the JSON feed.',
  Wazuh: 'A localfile command that curls the CSV feed and matches indicator values.',
  FortiSIEM: 'An HTTP worker or reference collection against the CSV.',
  CrowdStrike: 'Use outbound push (config/push.yaml). Falcon is push-based, not pull.',
  QRadar: 'A custom property or store-and-collect HTTP source on the JSON feed.',
  Sentinel: 'A Logic App or custom connector on the JSON or STIX feed.',
  Other: 'Any HTTP client that can send the X-API-Key header.',
}

export default function ApiPage({ notify }: { notify: (m: string, e?: boolean) => void }) {
  const base = window.location.origin
  const key = getKey()
  const short = key ? `${key.slice(0, 11)}...` : '<key>'

  const [keys, setKeys] = useState<ApiKey[]>([])
  const [users, setUsers] = useState<DashboardUser[]>([])
  const [roles, setRoles] = useState<RoleInfo[]>([])
  const [showRevoked, setShowRevoked] = useState(false)
  const [newKey, setNewKey] = useState('')
  const [keyName, setKeyName] = useState('')
  const [keyScopes, setKeyScopes] = useState('read')
  const [keyPlatform, setKeyPlatform] = useState('')
  const [error, setError] = useState('')
  const [userError, setUserError] = useState('')

  async function refreshKeys() {
    try {
      const r = await api.keys(showRevoked)
      setKeys(r.items)
    } catch {
      setKeys([])
    }
  }

  async function refreshUsers() {
    try {
      const r = await api.users()
      setUsers(r.users)
      setRoles(r.roles)
    } catch {
      // Not an admin: hide the users card entirely.
      setUsers([])
      setRoles([])
    }
  }

  useEffect(() => {
    void refreshKeys()
    void refreshUsers()
  }, [showRevoked])

  async function createKey() {
    setError('')
    try {
      const r = await api.createKey({
        name: keyName.trim(),
        scopes: keyScopes,
        platform: keyPlatform,
      })
      setNewKey(r.key)
      setKeyName('')
      await refreshKeys()
      notify('key created, copy it now')
    } catch (err) {
      setError(err instanceof Error ? err.message : 'could not create key')
    }
  }

  async function rotateKey(id: number, name: string) {
    if (!confirm(`Rotate "${name}"? The old key stops working immediately.`)) return
    try {
      const r = await api.rotateKey(id)
      setNewKey(r.key)
      await refreshKeys()
    } catch (err) {
      setError(err instanceof Error ? err.message : 'rotate failed')
    }
  }

  async function revokeKey(id: number, name: string) {
    if (!confirm(`Revoke "${name}"? It will stop working immediately.`)) return
    try {
      await api.revokeKey(id)
      await refreshKeys()
    } catch (err) {
      setError(err instanceof Error ? err.message : 'revoke failed')
    }
  }

  async function changeRole(id: number, role: Role) {
    setUserError('')
    try {
      await api.setUserRole(id, role)
      await refreshUsers()
      notify('role updated')
    } catch (err) {
      setUserError(err instanceof Error ? err.message : 'could not change role')
      await refreshUsers()
    }
  }

  async function toggleDisabled(u: DashboardUser) {
    setUserError('')
    try {
      await api.setUserDisabled(u.id, !u.disabled)
      await refreshUsers()
    } catch (err) {
      setUserError(err instanceof Error ? err.message : 'could not update account')
    }
  }

  async function copy(text: string) {
    try {
      await navigator.clipboard.writeText(text)
      notify('copied')
    } catch {
      notify('copy failed, select it in the box', true)
    }
  }

  return (
    <div className="flex flex-col gap-4">
      <div className="grid grid-cols-2 gap-3 max-md:grid-cols-1">
        <InfoCard title="Base URL">
          <code className="font-mono text-[12px] break-all">{base}/api/v1</code>
          <p className="mt-1.5 text-[12px] text-dim">Endpoint root, versioned under /api/v1.</p>
        </InfoCard>
        <InfoCard title="Authentication">
          <code className="font-mono text-[12px]">X-API-Key: {short}</code>
          <p className="mt-1.5 text-[12px] text-dim">
            Also accepted: Authorization Bearer, or ?apikey=. Scopes: read / write / admin.
          </p>
        </InfoCard>
        <SnippetCard
          title="Pull feed (CSV)"
          code={`curl -H "X-API-Key: ${key || 'iok_...'}" \\\n  "${base}/api/v1/feed?format=csv&min_severity=HIGH&view=importable"`}
          onCopy={copy}
        />
        <SnippetCard
          title="Pull feed (JSON)"
          code={`curl -H "X-API-Key: ${key || 'iok_...'}" \\\n  "${base}/api/v1/feed?format=json&view=malware"`}
          onCopy={copy}
        />
        <SnippetCard
          title="Pull feed (STIX 2.1)"
          code={`curl -H "X-API-Key: ${key || 'iok_...'}" \\\n  "${base}/api/v1/feed?format=stix"`}
          onCopy={copy}
        />
        <SnippetCard
          title="Single IOC"
          code={`curl -H "X-API-Key: ${key || 'iok_...'}" \\\n  "${base}/api/v1/iocs/Domain/evil.example.com"`}
          onCopy={copy}
        />

        <div className="card col-span-2 max-md:col-span-1">
          <h3 className="card-h">Query parameters</h3>
          <table className="w-full border-collapse text-[12px]">
            <thead>
              <tr>
                <th className="py-1 text-left text-[10px] uppercase tracking-[0.07em] text-faint">
                  Param
                </th>
                <th className="py-1 text-left text-[10px] uppercase tracking-[0.07em] text-faint">
                  Meaning
                </th>
              </tr>
            </thead>
            <tbody>
              {[
                ['view', 'master, c2, malware, importable'],
                ['min_severity', 'CRITICAL, HIGH, MEDIUM, LOW (single value, threshold)'],
                ['q', 'full-text search over value, family, actor, description, tags'],
                ['ioc_type, severity, confidence, category, malware_family, threat_actor', 'comma-separated filters'],
                ['folder_id', 'only members of one folder'],
                ['since, seen_since', 'updated_at / last_seen cutoffs'],
                ['sort, order, limit, offset, format', 'sorting, pagination, json / csv / stix'],
              ].map(([p, m]) => (
                <tr key={p} className="border-b border-line align-top">
                  <td className="py-1.5 pr-3 font-mono">{p}</td>
                  <td className="py-1.5 text-dim">{m}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      <section className="card">
        <div className="mb-1.5 flex items-center justify-between">
          <h3 className="card-h">API keys</h3>
          <Button className="py-1 text-[11.5px]" onClick={() => setShowRevoked((s) => !s)}>
            {showRevoked ? 'hide revoked' : 'show revoked'}
          </Button>
        </div>
        <p className="text-[12px] text-dim">
          Keys are shown only once at creation. Rotate them if lost.
        </p>

        <div className="mt-2 overflow-x-auto">
          <table className="w-full border-collapse text-[12px]">
            <thead>
              <tr className="text-left text-[10px] uppercase tracking-[0.07em] text-faint">
                <th className="py-1.5 pr-3">Name</th>
                <th className="py-1.5 pr-3">Scopes</th>
                <th className="py-1.5 pr-3">Platform</th>
                <th className="py-1.5 pr-3">Prefix</th>
                <th className="py-1.5 pr-3">Last used</th>
                <th className="py-1.5 pr-3">Uses</th>
                <th className="py-1.5 pr-3">Last IP</th>
                <th />
              </tr>
            </thead>
            <tbody>
              {keys.length === 0 && (
                <tr>
                  <td colSpan={8} className="py-6 text-center">
                    <p className="text-dim">No API keys yet.</p>
                    <p className="mt-1 text-[12px] text-faint">
                      Create one below to let a SIEM pull the feed. Keys are shown once, so copy the
                      new key when you create it.
                    </p>
                  </td>
                </tr>
              )}
              {keys.map((k) => (
                <tr key={k.id} className="border-t border-line">
                  <td className="py-1.5 pr-3">
                    {k.name}
                    {k.revoked && <span className="ml-1 text-faint">(revoked)</span>}
                  </td>
                  <td className="py-1.5 pr-3 font-mono text-dim">{k.scopes}</td>
                  <td className="py-1.5 pr-3">
                    {k.platform ? (
                      <span className="rounded-[4px] bg-bg4 px-1.5 py-0.5 text-[11px]">
                        {k.platform}
                      </span>
                    ) : (
                      <span className="text-faint">-</span>
                    )}
                  </td>
                  <td className="py-1.5 pr-3 font-mono text-dim">{k.prefix}...</td>
                  <td className="py-1.5 pr-3 font-mono text-[11px] text-dim">
                    {k.last_used_at?.slice(0, 16) || 'never'}
                  </td>
                  <td className="py-1.5 pr-3 text-dim">{num(k.uses)}</td>
                  <td className="py-1.5 pr-3 font-mono text-[11px] text-dim">{k.last_ip || '-'}</td>
                  <td className="py-1.5 whitespace-nowrap">
                    <Button className="mr-1 py-0.5 text-[11.5px]" onClick={() => rotateKey(k.id, k.name)}>
                      Rotate
                    </Button>
                    <Button
                      className="py-0.5 text-[11.5px]"
                      onClick={() => revokeKey(k.id, k.name)}
                      disabled={k.revoked}
                    >
                      Revoke
                    </Button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>

        {newKey && (
          <div className="mt-2 rounded-ctl border border-accent bg-accent-dim px-3 py-2">
            <p className="text-[12px] text-accent-ink">
              New key (shown once, copy it now):
            </p>
            <code className="mt-1 block font-mono text-[12px] break-all">{newKey}</code>
          </div>
        )}

        <div className="mt-3 flex flex-wrap items-center gap-2">
          <input
            className="ctl"
            placeholder="key name (e.g. splunk-prod)"
            value={keyName}
            onChange={(e) => setKeyName(e.target.value)}
            aria-label="Key name"
          />
          <select
            className="ctl"
            value={keyScopes}
            onChange={(e) => setKeyScopes(e.target.value)}
            aria-label="Scopes"
          >
            <option value="read">read</option>
            <option value="read,write">read,write</option>
            <option value="admin">admin</option>
          </select>
          <select
            className="ctl"
            value={keyPlatform}
            onChange={(e) => setKeyPlatform(e.target.value)}
            aria-label="Platform"
          >
            <option value="">Platform...</option>
            {PLATFORMS.map((p) => (
              <option key={p} value={p}>
                {p}
              </option>
            ))}
          </select>
          <Button variant="primary" onClick={createKey} disabled={!keyName.trim()}>
            Create
          </Button>
        </div>
        {keyPlatform && (
          <p className="mt-2 rounded-ctl border border-line bg-bg1 px-3 py-2 text-[12px] text-dim">
            {PLATFORM_HINTS[keyPlatform] ?? PLATFORM_HINTS.Other}
          </p>
        )}
        <ErrorText>{error}</ErrorText>
      </section>

      {users.length > 0 && (
        <section className="card">
          <div className="mb-1 flex items-center justify-between">
            <h3 className="card-h">Dashboard users</h3>
            <span className="text-[12px] text-dim">Accounts that can sign in to this dashboard</span>
          </div>
          <p className="text-[12px] text-dim">
            Roles control what each account can do. Administrators grant the admin role, it cannot
            be self-assigned at sign-up.
          </p>

          <table className="mt-2 w-full border-collapse text-[12px]">
            <thead>
              <tr className="text-left text-[10px] uppercase tracking-[0.07em] text-faint">
                <th className="py-1.5 pr-3">User</th>
                <th className="py-1.5 pr-3">Role</th>
                <th className="py-1.5 pr-3">Status</th>
                <th className="py-1.5 pr-3">Created</th>
                <th className="py-1.5 pr-3">Last login</th>
                <th />
              </tr>
            </thead>
            <tbody>
              {users.map((u) => (
                <tr key={u.id} className="border-t border-line">
                  <td className="py-1.5 pr-3">
                    <strong>{u.username}</strong>
                    {u.full_name && <span className="ml-1 text-faint">{u.full_name}</span>}
                  </td>
                  <td className="py-1.5 pr-3">
                    <span className={`rounded-[4px] border px-1.5 py-0.5 text-[11px] ${roleBadge(u.role)}`}>
                      {u.role}
                    </span>
                  </td>
                  <td className="py-1.5 pr-3">
                    {u.disabled ? <span className="text-faint">disabled</span> : <span className="text-ok">active</span>}
                  </td>
                  <td className="py-1.5 pr-3 text-dim">{u.created_at?.slice(0, 10)}</td>
                  <td className="py-1.5 pr-3 text-dim">
                    {(u.last_login_at || 'never').slice(0, 16)}
                  </td>
                  <td className="py-1.5 whitespace-nowrap">
                    <select
                      className="ctl mr-1 py-1"
                      value={u.role}
                      onChange={(e) => changeRole(u.id, e.target.value as Role)}
                      aria-label={`Role for ${u.username}`}
                    >
                      {(roles.length ? roles.map((r) => r.role) : ['viewer', 'analyst', 'admin']).map(
                        (r) => (
                          <option key={r} value={r}>
                            {r}
                          </option>
                        ),
                      )}
                    </select>
                    <Button className="py-1 text-[11.5px]" onClick={() => toggleDisabled(u)}>
                      {u.disabled ? 'Enable' : 'Disable'}
                    </Button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
          <ErrorText>{userError}</ErrorText>
        </section>
      )}
    </div>
  )
}

function roleBadge(role: Role): string {
  switch (role) {
    case 'admin':
      return 'border-danger bg-[rgb(229_72_77/0.15)] text-[#FFA6A6]'
    case 'analyst':
      return 'border-high bg-[rgb(240_165_60/0.15)] text-[#FFD08A]'
    default:
      return 'border-ok bg-[rgb(63_185_80/0.15)] text-[#9BE8A8]'
  }
}

function InfoCard({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <div className="card">
      <h3 className="card-h">{title}</h3>
      {children}
    </div>
  )
}

function SnippetCard({
  title,
  code,
  onCopy,
}: {
  title: string
  code: string
  onCopy: (text: string) => void
}) {
  return (
    <div className="card">
      <div className="mb-1 flex items-center justify-between">
        <h3 className="card-h">{title}</h3>
        <Button className="px-1.5 py-0.5 text-[11.5px]" onClick={() => onCopy(code)} aria-label={`Copy ${title} command`}>
          <Copy size={13} />
        </Button>
      </div>
      <pre className="overflow-x-auto whitespace-pre-wrap break-all rounded-ctl border border-line bg-bg1 p-2 font-mono text-[11.5px] text-dim">
        {code}
      </pre>
    </div>
  )
}