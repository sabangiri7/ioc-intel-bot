import { useEffect, useState, type FormEvent } from 'react'
import { ShieldCheck, Key, UserPlus } from '@phosphor-icons/react'
import { api, setKey, type Role } from '../lib/api'
import { Button, ErrorText } from '../lib/ui'

type Mode = 'signin' | 'register'

/** Roles offered at sign-up. "admin" is deliberately not self-assignable. */
const ROLE_OPTIONS: { value: Role; label: string; help: string }[] = [
  {
    value: 'viewer',
    label: 'Viewer: can search, view and export IOCs',
    help: 'Read-only. Good for analysts who mainly review and triage indicators.',
  },
  {
    value: 'analyst',
    label: 'Analyst: can also create, edit and delete IOCs',
    help: 'Read and write. Use if you need to curate, correct or remove indicators.',
  },
]

export default function Login({ onSignedIn }: { onSignedIn: () => void }) {
  const [mode, setMode] = useState<Mode>('signin')
  const [firstRun, setFirstRun] = useState(false)
  const [registrationOpen, setRegistrationOpen] = useState(false)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  const [showKeyInput, setShowKeyInput] = useState(false)

  // username / password / key
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [fullName, setFullName] = useState('')
  const [role, setRole] = useState<Role>('viewer')
  const [rawKey, setRawKey] = useState('')

  useEffect(() => {
    void api
      .authStatus()
      .then((s) => {
        setFirstRun(s.auth_required && !s.has_users)
        setRegistrationOpen(!s.auth_required || s.has_users ? s.allow_registration : false)
      })
      .catch(() => {
        /* keep the sign-in form if the status probe fails */
      })
  }, [])

  const activeRole = ROLE_OPTIONS.find((r) => r.value === role)

  function switchMode(next: Mode) {
    setMode(next)
    setError('')
  }

  async function submitSignIn(e: FormEvent) {
    e.preventDefault()
    setError('')
    if (!username || !password) {
      setError('enter your username and password')
      return
    }
    setBusy(true)
    try {
      const res = await api.login(username.trim(), password)
      setKey(res.key)
      onSignedIn()
    } catch (err) {
      setError(err instanceof Error ? err.message : 'sign in failed')
    } finally {
      setBusy(false)
    }
  }

  async function submitRegister(e: FormEvent) {
    e.preventDefault()
    setError('')
    if (!username.trim() || password.length < 8) {
      setError('username required, password at least 8 characters')
      return
    }
    setBusy(true)
    try {
      const res = await api.register({
        username: username.trim(),
        password,
        full_name: fullName.trim(),
        role: firstRun ? 'admin' : role,
      })
      setKey(res.key)
      onSignedIn()
    } catch (err) {
      setError(err instanceof Error ? err.message : 'registration failed')
    } finally {
      setBusy(false)
    }
  }

  async function submitKey(e: FormEvent) {
    e.preventDefault()
    setError('')
    const prev = rawKey.trim()
    if (!prev) {
      setError('paste an API key first')
      return
    }
    setBusy(true)
    try {
      setKey(prev)
      await api.stats()
      onSignedIn()
    } catch {
      setError('that key was rejected')
      setKey('')
    } finally {
      setBusy(false)
    }
  }

  const registering = mode === 'register' && !firstRun

  return (
    <div className="fixed inset-0 z-[100] overflow-y-auto bg-bg0">
      <div
        className="pointer-events-none fixed inset-0"
        style={{
          background:
            'radial-gradient(1100px 500px at 12% -8%, rgb(61 155 250 / 0.14), transparent 60%),' +
            'radial-gradient(900px 460px at 105% 8%, rgb(63 185 80 / 0.07), transparent 55%),' +
            'linear-gradient(rgb(61 155 250 / 0.045) 1px, transparent 1px) 0 0 / 100% 44px,' +
            'linear-gradient(90deg, rgb(61 155 250 / 0.045) 1px, transparent 1px) 0 0 / 44px 100%',
        }}
        aria-hidden="true"
      />

      <div className="relative mx-auto grid min-h-full max-w-[1120px] grid-cols-[minmax(0,1.05fr)_minmax(360px,460px)] items-center gap-10 px-7 py-12 max-md:grid-cols-1 max-md:gap-8">
        <section className="max-w-[560px] max-md:justify-self-stretch">
          <div className="flex items-center gap-2">
            <ShieldCheck size={22} className="flex-none text-accent" weight="regular" />
            <div>
              <strong className="text-[14px] font-bold tracking-[0.14em]">IOC&nbsp;INTEL</strong>
              <p className="mt-0.5 text-dim">Threat-intelligence command center</p>
            </div>
          </div>

          <h1 className="mb-3 mt-6 text-[34px] font-bold leading-[1.2] tracking-tight">
            Threat indicators, collected &amp; scored for analyst review.
          </h1>
          <p className="mb-6 max-w-[60ch] text-[15px] leading-[1.62] text-dim">
            This command center aggregates <strong className="text-text">C2</strong>,{' '}
            <strong className="text-text">malware distribution</strong>, and{' '}
            <strong className="text-text">cracked&nbsp;/&nbsp;pirated-software</strong> indicators
            from public threat-intelligence feeds, deduplicates and scores them, and prepares them
            for <em>manual</em> review and import.
          </p>

          <ul className="m-0 grid list-none gap-3 p-0">
            {[
              ['READ-ONLY', 'public feeds, advisories and vendor blogs.'],
              ['NO RESPONSE ACTION', 'nothing is blocked or contained.'],
              ['ANALYST IN THE LOOP', 'outputs require human review.'],
            ].map(([k, v]) => (
              <li
                key={k}
                className="flex items-baseline gap-2.5 rounded-card border border-line bg-[rgb(18_25_34/0.55)] px-3.5 py-2.5 text-[13.5px] text-dim"
              >
                <span className="whitespace-nowrap text-[11px] font-semibold uppercase tracking-[0.06em] text-accent">
                  {k}
                </span>
                <span>{v}</span>
              </li>
            ))}
          </ul>
        </section>

        <section className="w-full max-md:justify-self-stretch">
          <div className="flex flex-col gap-3 rounded-[14px] border border-line2 bg-bg2 p-6 shadow-xl">
            {registering ? (
              <form onSubmit={submitRegister} className="flex flex-col" autoComplete="on">
                <h2 className="mb-1 text-[19px]">Create an account</h2>
                <p className="text-dim">Register to get dashboard access.</p>

                <label className="label mt-3" htmlFor="reg-username">
                  Username
                </label>
                <input
                  id="reg-username"
                  className="ctl"
                  value={username}
                  onChange={(e) => setUsername(e.target.value)}
                  placeholder="your.name"
                  autoComplete="username"
                />

                <label className="label mt-3" htmlFor="reg-fullname">
                  Full name (optional)
                </label>
                <input
                  id="reg-fullname"
                  className="ctl"
                  value={fullName}
                  onChange={(e) => setFullName(e.target.value)}
                  placeholder="Jane Analyst"
                  autoComplete="name"
                />

                <label className="label mt-3" htmlFor="reg-role">
                  Access level
                </label>
                <select
                  id="reg-role"
                  className="ctl"
                  value={role}
                  onChange={(e) => setRole(e.target.value as Role)}
                >
                  {ROLE_OPTIONS.map((r) => (
                    <option key={r.value} value={r.value}>
                      {r.label}
                    </option>
                  ))}
                </select>
                {activeRole && (
                  <p className="mt-1.5 text-[12px] leading-[1.45] text-dim">{activeRole.help}</p>
                )}

                <label className="label mt-3" htmlFor="reg-password">
                  Password
                </label>
                <input
                  id="reg-password"
                  type="password"
                  className="ctl"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  placeholder="at least 8 characters"
                  autoComplete="new-password"
                />

                <Button variant="primary" type="submit" disabled={busy} className="mt-3 w-full py-2.5">
                  {busy ? 'Creating account...' : 'Create account and sign in'}
                </Button>
                <ErrorText>{error}</ErrorText>
                <p className="mt-2.5 text-[12px] italic text-dim">
                  Administrator access is granted by an existing admin, not at sign-up.
                </p>
              </form>
            ) : firstRun ? (
              <form onSubmit={submitRegister} className="flex flex-col" autoComplete="on">
                <h2 className="mb-1 text-[19px]">Create the administrator account</h2>
                <p className="text-dim">First run. Set up the initial dashboard user, then sign in.</p>

                <label className="label mt-3" htmlFor="prov-username">
                  Username
                </label>
                <input
                  id="prov-username"
                  className="ctl"
                  value={username}
                  onChange={(e) => setUsername(e.target.value)}
                  placeholder="analyst"
                  autoComplete="username"
                />

                <label className="label mt-3" htmlFor="prov-password">
                  Password
                </label>
                <input
                  id="prov-password"
                  type="password"
                  className="ctl"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  placeholder="at least 8 characters"
                  autoComplete="new-password"
                />

                <Button variant="primary" type="submit" disabled={busy} className="mt-3 w-full py-2.5">
                  {busy ? 'Creating account...' : 'Create account and sign in'}
                </Button>
                <ErrorText>{error}</ErrorText>
              </form>
            ) : (
              <>
                <h2 className="mb-1 text-[19px]">Sign in</h2>
                <p className="text-dim">Use your dashboard account.</p>

                <form onSubmit={submitSignIn} className="flex flex-col" autoComplete="on">
                  <label className="label mt-3" htmlFor="login-username">
                    Username
                  </label>
                  <input
                    id="login-username"
                    className="ctl"
                    value={username}
                    onChange={(e) => setUsername(e.target.value)}
                    placeholder="analyst"
                    autoComplete="username"
                  />

                  <label className="label mt-3" htmlFor="login-password">
                    Password
                  </label>
                  <input
                    id="login-password"
                    type="password"
                    className="ctl"
                    value={password}
                    onChange={(e) => setPassword(e.target.value)}
                    placeholder="--------"
                    autoComplete="current-password"
                  />

                  <Button variant="primary" type="submit" disabled={busy} className="mt-4 w-full py-2.5">
                    {busy ? 'Signing in...' : 'Sign in'}
                  </Button>
                  <ErrorText>{error}</ErrorText>
                </form>
              </>
            )}

            {!firstRun && (
              <>
                <div className="my-4 border-t border-line" />

                {!showKeyInput ? (
                  <div className="flex gap-2">
                    {registrationOpen && (
                      <button
                        type="button"
                        onClick={() => switchMode(mode === 'register' ? 'signin' : 'register')}
                        className="flex-1 cursor-pointer rounded-ctl border border-line2 bg-transparent py-1.5 text-dim transition-colors hover:border-accent hover:bg-bg4 hover:text-text"
                      >
                        {mode === 'register' ? (
                          'Back to sign in'
                        ) : (
                          <span className="inline-flex items-center justify-center gap-1.5">
                            <UserPlus size={14} /> Create an account
                          </span>
                        )}
                      </button>
                    )}
                    <button
                      type="button"
                      onClick={() => setShowKeyInput(true)}
                      className="flex-1 cursor-pointer rounded-ctl border border-line2 bg-transparent py-1.5 text-dim transition-colors hover:border-accent hover:bg-bg4 hover:text-text"
                    >
                      <span className="inline-flex items-center justify-center gap-1.5">
                        <Key size={14} /> Use an API key
                      </span>
                    </button>
                  </div>
                ) : (
                  <form onSubmit={submitKey} className="flex flex-col">
                    <p className="text-[12px] text-dim">
                      Paste a machine key (<code className="font-mono">iok_...</code>) to open the
                      dashboard.
                    </p>
                    <input
                      className="ctl mt-2"
                      type="password"
                      value={rawKey}
                      onChange={(e) => setRawKey(e.target.value)}
                      placeholder="iok_..."
                      aria-label="API key"
                    />
                    <Button type="submit" disabled={busy} className="mt-2 w-full">
                      Connect with key
                    </Button>
                    <ErrorText>{error}</ErrorText>
                    <button
                      type="button"
                      onClick={() => {
                        setShowKeyInput(false)
                        setError('')
                      }}
                      className="mt-2 cursor-pointer text-[12px] text-faint hover:text-text"
                    >
                      Back
                    </button>
                  </form>
                )}

                <p className="mt-4 break-words text-[12px] leading-[1.5] text-faint">
                  Key management:{' '}
                  <code className="text-[11px]">
                    python3 -m iocbot.keys create &lt;name&gt; --scopes read,write,admin --platform
                    Splunk
                  </code>
                </p>
              </>
            )}
          </div>
        </section>
      </div>
    </div>
  )
}