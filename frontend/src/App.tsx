import { useCallback, useEffect, useMemo, useState } from 'react'
import { NavLink, Navigate, Route, Routes, useLocation, useNavigate } from 'react-router-dom'

import { Alert, Loader } from './components/ui'
import { api, configureApi, type AuthConfig, type Me } from './lib/api'
import {
  clearSession,
  completeLogin,
  loadSession,
  localLogin,
  logout,
  refresh,
  startLogin,
  type Session,
} from './lib/auth'
import AddPackages from './pages/AddPackages'
import Audit from './pages/Audit'
import PackagesBase from './pages/PackagesBase'
import Profile from './pages/Profile'
import QueueLegal from './pages/QueueLegal'
import QueueSecurity from './pages/QueueSecurity'
import RequestCard from './pages/RequestCard'
import RequestList from './pages/RequestList'
import SettingsPage from './pages/SettingsPage'

export default function App() {
  const [config, setConfig] = useState<AuthConfig | null>(null)
  const [session, setSession] = useState<Session | null>(() => loadSession())
  const [me, setMe] = useState<Me | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [counters, setCounters] = useState<Record<string, number>>({})
  const location = useLocation()

  const handleUnauthorized = useCallback(() => {
    clearSession()
    setSession(null)
    setMe(null)
  }, [])

  useEffect(() => {
    configureApi(() => loadSession()?.access_token ?? null, handleUnauthorized)
  }, [handleUnauthorized])

  useEffect(() => {
    api.authConfig().then(setConfig).catch((exc: Error) => setError(exc.message))
  }, [])

  useEffect(() => {
    if (!session) {
      setMe(null)
      return
    }
    api
      .me()
      .then(setMe)
      .catch((exc: Error) => setError(exc.message))
  }, [session])

  // Продление токена до истечения срока.
  useEffect(() => {
    if (!session || !config || session.kind !== 'oidc') return
    const delay = Math.max(session.expires_at - Date.now() - 60_000, 15_000)
    const timer = setTimeout(() => {
      refresh(config, session).then((next) => (next ? setSession(next) : handleUnauthorized()))
    }, delay)
    return () => clearTimeout(timer)
  }, [session, config, handleUnauthorized])

  const reloadCounters = useCallback(() => {
    if (!session) return
    api.queueCounters().then(setCounters).catch(() => setCounters({}))
  }, [session])

  useEffect(() => {
    reloadCounters()
    const timer = setInterval(reloadCounters, 30_000)
    return () => clearInterval(timer)
  }, [reloadCounters, location.pathname])

  if (location.pathname === '/auth/callback') {
    return <Callback config={config} onSession={setSession} />
  }

  if (!config) {
    return <div className="content">{error ? <Alert kind="error">{error}</Alert> : <Loader />}</div>
  }

  if (!session || !me) {
    return (
      <Login
        config={config}
        error={error}
        onError={setError}
        onSession={(next) => {
          setError(null)
          setSession(next)
        }}
      />
    )
  }

  return (
    <div className="layout">
      <Sidebar me={me} config={config} counters={counters} />
      <main className="content">
        {error ? <Alert kind="error">{error}</Alert> : null}
        <Routes>
          <Route path="/" element={<Navigate to="/add" replace />} />
          <Route path="/add" element={<AddPackages me={me} config={config} />} />
          <Route path="/requests" element={<RequestList me={me} scope="mine" />} />
          <Route path="/requests/all" element={<RequestList me={me} scope="all" />} />
          <Route path="/requests/:id" element={<RequestCard me={me} onChange={reloadCounters} />} />
          <Route path="/packages" element={<PackagesBase me={me} />} />
          <Route path="/queue/security" element={<QueueSecurity onChange={reloadCounters} />} />
          <Route path="/queue/legal" element={<QueueLegal onChange={reloadCounters} />} />
          <Route path="/settings" element={<SettingsPage me={me} />} />
          <Route path="/audit" element={<Audit />} />
          <Route path="/profile" element={<Profile me={me} config={config} />} />
          <Route path="*" element={<Alert kind="warn">Страница не найдена</Alert>} />
        </Routes>
      </main>
    </div>
  )
}

function Sidebar({
  me,
  config,
  counters,
}: {
  me: Me
  config: AuthConfig
  counters: Record<string, number>
}) {
  const isSec = me.roles.includes('devsecops') || me.roles.includes('admin')
  const isLegal = me.roles.includes('legal') || me.roles.includes('admin')
  const isAdmin = me.roles.includes('admin')

  return (
    <nav className="sidebar">
      <div className="brand">
        {config.app_name}
        <small>
          {config.app_env === 'prod' ? 'production' : config.app_env} · единственный вход для пакетов
        </small>
      </div>

      <div className="nav-group">Работа с пакетами</div>
      <NavItem to="/add" label="Добавить пакеты" />
      <NavItem to="/requests" label="Мои заявки" />
      {isSec || isLegal || isAdmin ? <NavItem to="/requests/all" label="Все заявки" /> : null}
      <NavItem to="/packages" label="База пакетов" />

      {isSec || isLegal ? <div className="nav-group">Очереди</div> : null}
      {isSec ? (
        <NavItem
          to="/queue/security"
          label="DevSecOps"
          count={(counters.security ?? 0) + (counters.quarantined ?? 0)}
        />
      ) : null}
      {isLegal ? <NavItem to="/queue/legal" label="Юристы" count={counters.legal ?? 0} /> : null}

      <div className="nav-group">Сервис</div>
      <NavItem to="/settings" label="Настройка" />
      {isAdmin ? <NavItem to="/audit" label="Аудит-лог" /> : null}
      <NavItem
        to="/profile"
        label="Профиль"
        count={counters.unread_notifications ?? 0}
        muted
      />

      <div className="spacer" />
      <div className="nav-group">{me.display_name}</div>
      <div className="nav-link" style={{ cursor: 'default' }}>
        <span className="small muted">{me.roles.join(', ') || 'без ролей'}</span>
      </div>
      <button className="ghost small" style={{ margin: '4px 14px' }} onClick={() => logout(config)}>
        Выйти
      </button>
    </nav>
  )
}

function NavItem({
  to,
  label,
  count,
  muted,
}: {
  to: string
  label: string
  count?: number
  muted?: boolean
}) {
  return (
    <NavLink to={to} className={({ isActive }) => `nav-link${isActive ? ' active' : ''}`}>
      <span>{label}</span>
      {count ? <span className={`nav-count${muted ? ' muted' : ''}`}>{count}</span> : null}
    </NavLink>
  )
}

function Login({
  config,
  error,
  onError,
  onSession,
}: {
  config: AuthConfig
  error: string | null
  onError: (message: string) => void
  onSession: (session: Session) => void
}) {
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [busy, setBusy] = useState(false)

  return (
    <div className="content login">
      <h1>{config.app_name}</h1>
      <p className="page-hint">
        Вход через SSO. Заводить пакеты можно только здесь — правка <code>package_list.txt</code> и
        merge request'ы не поддерживаются.
      </p>
      {error ? <Alert kind="error">{error}</Alert> : null}
      <div className="card">
        <button
          className="primary"
          style={{ width: '100%' }}
          onClick={() => startLogin(config).catch((exc: Error) => onError(exc.message))}
        >
          Войти через SSO
        </button>
      </div>
      {config.local_auth_enabled ? (
        <div className="card">
          <h2>Сервисная учётная запись</h2>
          <p className="small muted">
            Fallback-вход логин/пароль. В production отключён (<code>LOCAL_AUTH_ENABLED=false</code>).
          </p>
          <form
            onSubmit={(event) => {
              event.preventDefault()
              setBusy(true)
              localLogin(username, password)
                .then(onSession)
                .catch((exc: Error) => onError(exc.message))
                .finally(() => setBusy(false))
            }}
          >
            <label>
              <span>Логин</span>
              <input className="wide" value={username} onChange={(e) => setUsername(e.target.value)} />
            </label>
            <label>
              <span>Пароль</span>
              <input
                className="wide"
                type="password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
              />
            </label>
            <button type="submit" disabled={busy || !username || !password}>
              {busy ? 'Вход…' : 'Войти'}
            </button>
          </form>
        </div>
      ) : null}
    </div>
  )
}

function Callback({
  config,
  onSession,
}: {
  config: AuthConfig | null
  onSession: (session: Session) => void
}) {
  const navigate = useNavigate()
  const [error, setError] = useState<string | null>(null)
  const params = useMemo(() => new URLSearchParams(window.location.search), [])

  useEffect(() => {
    if (!config) return
    const code = params.get('code')
    const state = params.get('state')
    const oidcError = params.get('error_description') || params.get('error')
    if (oidcError) {
      setError(`Провайдер отклонил вход: ${oidcError}`)
      return
    }
    if (!code || !state) {
      setError('В ответе провайдера нет кода авторизации')
      return
    }
    completeLogin(config, code, state)
      .then((from) => {
        const session = loadSession()
        if (session) onSession(session)
        navigate(from, { replace: true })
      })
      .catch((exc: Error) => setError(exc.message))
  }, [config, params, navigate, onSession])

  return (
    <div className="content login">
      {error ? (
        <>
          <Alert kind="error">{error}</Alert>
          <button onClick={() => navigate('/', { replace: true })}>Начать заново</button>
        </>
      ) : (
        <Loader text="Завершаем вход…" />
      )}
    </div>
  )
}
