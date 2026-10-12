/**
 * Typed client for the FastAPI backend (python3 -m iocbot.api.server).
 *
 * Auth: every /api/v1 call needs a key. We send `X-API-Key`. Session keys come
 * from login/registration; machine keys can be pasted on the login screen.
 * The key is kept in localStorage so a refresh does not sign the user out.
 */

export const KEY_STORAGE = 'ioc_key'

export type Role = 'viewer' | 'analyst' | 'admin'
export type Severity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW'
export type Confidence = Severity

export interface Ioc {
  ioc: string
  ioc_type: string
  threat?: string
  malware_family: string
  threat_actor: string
  campaign: string
  categories: string[]
  category?: string
  confidence: Confidence
  severity: Severity
  first_seen: string
  last_seen: string
  source?: string
  sources?: string[]
  sources_detail?: Record<string, unknown>
  evidence?: unknown
  description: string
  tags: string[]
  mitre_attack?: string[]
  crowdstrike_importable: string
  validation_status: string
  folders: string[]
  folders_id?: number[]
}

export interface SearchResult {
  total: number
  limit: number
  offset: number
  items: Ioc[]
}

export interface Stats {
  total: number
  by_severity: Partial<Record<Severity, number>>
  by_confidence: Partial<Record<Confidence, number>>
  by_type: Record<string, number>
  by_category: Record<string, number>
  by_validation: Record<string, number>
  importable: number
  new_today: number
  c2: number
  malware: number
  unreviewed: number
  folders: number
  last_cycle: { id: number; started: string; finished: string } | null
  generated_at?: string
}

export interface Folder {
  id: number
  name: string
  kind: 'auto' | 'manual'
  field: string
  value: string
  description: string
  color: string
  created_at: string
  count?: number
  group?: 'malware' | 'actor' | 'manual'
}

export interface ApiKey {
  id: number
  name: string
  scopes: string
  prefix: string
  platform: string
  created_at: string
  last_used_at: string
  uses: number
  last_ip: string
  revoked: boolean
}

export interface DashboardUser {
  id: number
  username: string
  full_name: string
  role: Role
  disabled: number
  created_at: string
  last_login_at: string
}

export interface RoleInfo {
  role: Role
  label: string
  scopes: string
}

export interface PushTarget {
  name: string
  type: string
  enabled: boolean
}

export interface PushLogEntry {
  target: string
  status: string
  sent: number
  detail: string
  pushed_at: string
}

export interface SearchFilters {
  q?: string
  view?: string
  ioc_type?: string[]
  severity?: string[]
  min_severity?: string
  folder_id?: number
  since?: string
  unreviewed?: boolean
  limit?: number
  offset?: number
  sort?: string
  order?: 'asc' | 'desc'
  format?: 'json' | 'csv' | 'stix'
}

export class ApiError extends Error {
  status: number
  constructor(status: number, message: string) {
    super(message)
    this.status = status
    this.name = 'ApiError'
  }
}

let apiKey = localStorage.getItem(KEY_STORAGE) ?? ''
const unauthorizedHandlers: Array<() => void> = []

export function getKey(): string {
  return apiKey
}

export function setKey(key: string): void {
  apiKey = key
  if (key) localStorage.setItem(KEY_STORAGE, key)
  else localStorage.removeItem(KEY_STORAGE)
}

/** Register a callback fired when the server rejects the current key. */
export function onUnauthorized(fn: () => void): void {
  unauthorizedHandlers.push(fn)
}

async function request<T>(path: string, init: RequestInit = {}): Promise<T> {
  const headers = new Headers(init.headers)
  if (apiKey) headers.set('X-API-Key', apiKey)
  if (init.body && !headers.has('Content-Type')) {
    headers.set('Content-Type', 'application/json')
  }

  const res = await fetch(`/api/v1${path}`, { ...init, headers })

  if (res.status === 401) {
    setKey('')
    unauthorizedHandlers.forEach((fn) => fn())
    throw new ApiError(401, 'API key required')
  }

  if (!res.ok) {
    let detail = res.statusText
    try {
      const body = await res.json()
      detail = typeof body.detail === 'string' ? body.detail : JSON.stringify(body.detail ?? body)
    } catch {
      /* non-JSON error body */
    }
    throw new ApiError(res.status, detail)
  }

  if (res.status === 204) return undefined as T
  const contentType = res.headers.get('content-type') ?? ''
  return (contentType.includes('json') ? res.json() : res.text()) as Promise<T>
}

const post = <T,>(p: string, body?: unknown) =>
  request<T>(p, { method: 'POST', body: body === undefined ? undefined : JSON.stringify(body) })
const put = <T,>(p: string, body: unknown) =>
  request<T>(p, { method: 'PUT', body: JSON.stringify(body) })
const del = <T,>(p: string) => request<T>(p, { method: 'DELETE' })

/** Serialise filters into a query string, omitting empty values. */
export function toQuery(filters: SearchFilters): string {
  const p = new URLSearchParams()
  const add = (k: string, v: unknown) => {
    if (v === undefined || v === null || v === '' ) return
    if (Array.isArray(v)) {
      if (v.length) p.set(k, v.join(','))
    } else {
      p.set(k, String(v))
    }
  }
  add('q', filters.q)
  add('view', filters.view)
  add('ioc_type', filters.ioc_type)
  add('severity', filters.severity)
  add('min_severity', filters.min_severity)
  add('folder_id', filters.folder_id)
  add('since', filters.since)
  add('unreviewed', filters.unreviewed ? 'true' : undefined)
  add('limit', filters.limit)
  add('offset', filters.offset)
  add('sort', filters.sort)
  add('order', filters.order)
  add('format', filters.format)
  return p.toString()
}

export const api = {
  stats: () => request<Stats>('/stats'),

  search: (f: SearchFilters) => request<SearchResult>(`/iocs?${toQuery(f)}`),

  getIoc: (type: string, value: string) =>
    request<Ioc>(`/iocs/${encodeURIComponent(type)}/${encodeURIComponent(value)}`),

  createIoc: (body: Partial<Ioc> & { ioc: string; ioc_type: string }) =>
    post<Ioc>('/iocs', body),
  updateIoc: (type: string, value: string, body: Partial<Ioc>) =>
    put<Ioc>(`/iocs/${encodeURIComponent(type)}/${encodeURIComponent(value)}`, body),
  deleteIoc: (type: string, value: string) =>
    del<{ deleted: boolean }>(`/iocs/${encodeURIComponent(type)}/${encodeURIComponent(value)}`),

  folders: (includeZero = false) => request<{ items: Folder[] }>(`/folders?include_zero=${includeZero}`),
  createFolder: (body: { name: string; description?: string; color?: string }) =>
    post<Folder>('/folders', body),
  updateFolder: (id: number, body: Partial<Folder>) => put<Folder>(`/folders/${id}`, body),
  deleteFolder: (id: number) => del<{ deleted: boolean }>(`/folders/${id}`),
  folderIocs: (id: number, f: SearchFilters) =>
    request<SearchResult>(`/folders/${id}/iocs?${toQuery(f)}`),
  addFolderIocs: (id: number, body: unknown) => post<{ added: number }>(`/folders/${id}/iocs`, body),
  removeFolderIoc: (id: number, type: string, value: string) =>
    del<{ removed: boolean }>(`/folders/${id}/iocs/${encodeURIComponent(type)}/${encodeURIComponent(value)}`),
  syncFolders: () => post<{ folders: number }>('/folders/sync'),

  keys: (includeRevoked = false) =>
    request<{ items: ApiKey[] }>(`/keys?include_revoked=${includeRevoked}`),
  createKey: (body: { name: string; scopes: string; platform?: string }) =>
    post<{ id: number; name: string; key: string }>('/keys', body),
  rotateKey: (id: number) => post<{ id: number; name: string; key: string }>(`/keys/${id}/rotate`),
  revokeKey: (id: number) => del<{ revoked: boolean }>(`/keys/${id}`),

  users: () => request<{ users: DashboardUser[]; roles: RoleInfo[] }>('/users'),
  setUserRole: (id: number, role: Role) => put<{ ok: boolean }>(`/users/${id}/role`, { role }),
  setUserDisabled: (id: number, disabled: boolean) =>
    put<{ ok: boolean }>(`/users/${id}/disabled`, { disabled }),

  authStatus: () =>
    request<{
      auth_required: boolean
      has_users: boolean
      allow_registration: boolean
      bootstrap_available: boolean
    }>('/auth/status'),
  login: (username: string, password: string) =>
    post<{ key: string; username: string; role: Role }>('/auth/login', { username, password }),
  register: (body: { username: string; password: string; full_name?: string; role: Role }) =>
    post<{ key: string; username: string; role: Role; first_user: boolean }>('/auth/register', body),
  me: () => request<{ name: string; scopes: string[]; username: string; role: string; method: string }>('/auth/me'),
  logout: () => post<{ ok: boolean }>('/auth/logout'),

  run: () => post<{ started: boolean }>('/run'),
  runStatus: () => request<{ running: boolean; last_stats: unknown; last_error: string }>('/run'),
  pushInfo: () =>
    request<{ enabled: boolean; targets: PushTarget[]; log: PushLogEntry[] }>('/push'),
  push: () => post<Record<string, unknown>>('/push'),
}

/** Trigger a client-side file download for an authenticated endpoint. */
export function downloadUrl(path: string, filters: SearchFilters): string {
  return `/api/v1${path}?${toQuery(filters)}&apikey=${encodeURIComponent(apiKey)}`
}