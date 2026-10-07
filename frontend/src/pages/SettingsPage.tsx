import { useState } from 'react'

import { Alert, Loader, formatTime, useAsync } from '../components/ui'
import { api, type AdminUser, type Me, type OIDCSettings, type SettingRow } from '../lib/api'

export default function SettingsPage({ me }: { me: Me }) {
  const settings = useAsync(() => api.settings(), [])
  const policies = useAsync(() => api.policies(), [])
  const system = useAsync(() => api.systemStatus(), [])
  const [message, setMessage] = useState<string | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [activeTab, setActiveTab] = useState<'general' | 'users' | 'oidc'>('general')
  const isAdmin = me.roles.includes('admin')
  const isSec = me.roles.includes('devsecops') || isAdmin

  const sections = new Map<string, typeof settings.data>()
  for (const row of settings.data ?? []) {
    const list = sections.get(row.section) ?? []
    list.push(row)
    sections.set(row.section, list as never)
  }

  return (
    <>
      <div className="topbar">
        <div>
          <h1>Настройка</h1>
          <p className="page-hint">
            Общие адреса и пороги можно сохранить здесь. Для их применения достаточно
            перезапустить <code>api-go</code> и <code>worker-go</code> — пересобирать образы не нужно.
            OIDC и его секрет на отдельной вкладке применяются сразу.
          </p>
        </div>
        {isAdmin ? (
          <button
            className="small"
            onClick={() => {
              setError(null)
              api
                .reloadConfig()
                .then((res) => {
                  setMessage(
                    `Перечитано: blacklist — ${res.blacklist?.rules} правил, лицензии — ` +
                      `${res.licenses?.allowed} разрешено / ${res.licenses?.forbidden} запрещено`,
                  )
                  policies.reload()
                })
                .catch((exc: Error) => setError(exc.message))
            }}
          >
            перечитать конфигурацию
          </button>
        ) : null}
      </div>

      <div className="settings-tabs">
        <button className={activeTab === 'general' ? 'active' : ''} onClick={() => setActiveTab('general')}>
          Конфигурация и состояние
        </button>
        {isAdmin ? (
          <button className={activeTab === 'users' ? 'active' : ''} onClick={() => setActiveTab('users')}>
            Пользователи и роли
          </button>
        ) : null}
        {isAdmin ? (
          <button className={activeTab === 'oidc' ? 'active' : ''} onClick={() => setActiveTab('oidc')}>
            OIDC / Keycloak
          </button>
        ) : null}
      </div>

      {activeTab === 'users' && isAdmin ? <UsersPanel /> : activeTab === 'oidc' && isAdmin ? <OIDCPanel /> : <>

      {message ? <Alert kind="ok">{message}</Alert> : null}
      {error ? <Alert kind="error">{error}</Alert> : null}
      {settings.error ? <Alert kind="error">{settings.error}</Alert> : null}
      {settings.loading ? <Loader /> : null}

      {system.data ? <QueueCard info={system.data} isAdmin={isAdmin} onDone={() => system.reload()} /> : null}

      {policies.data?.vuln_index ? <VulnIndexCard info={policies.data.vuln_index} isSec={isSec} /> : null}

      {[...sections.entries()].map(([section, rows]) => (
        <div className="card" key={section}>
          <h2>{section}</h2>
          <table>
            <thead>
              <tr>
                <th>Переменная</th>
                <th>Значение</th>
                <th>Описание</th>
                <th />
              </tr>
            </thead>
            <tbody>
              {(rows ?? []).map((row) => (
                <tr key={row.env}>
                  <td className="mono nowrap">{row.env}</td>
                  <SettingValue row={row} isAdmin={isAdmin} onSaved={(text) => {
                    setMessage(text)
                    settings.reload()
                  }} onError={setError} />
                  <td className="small dim">{row.description}</td>
                  <td className="small nowrap">
                    {row.overridden ? <span className="badge info">web</span> : <span className="muted">.env</span>}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ))}

      {policies.data?.blacklist ? (
        <div className="card">
          <h2>Blacklist</h2>
          <p className="small dim">
            Файл <code>{policies.data.blacklist.path}</code>, загружен{' '}
            {formatTime(policies.data.blacklist.loaded_at)}. Совпадение останавливает конвейер на
            шаге 1 — пакет не скачивается.
          </p>
          {policies.data.blacklist.error ? (
            <Alert kind="warn">Файл не загружен: {policies.data.blacklist.error}</Alert>
          ) : null}
          <table>
            <thead>
              <tr>
                <th>Менеджер</th>
                <th>Имя / glob</th>
                <th>Версии</th>
                <th>Причина</th>
                <th>Добавил</th>
              </tr>
            </thead>
            <tbody>
              {(policies.data.blacklist.rules ?? []).map((rule: Record<string, string>, i: number) => (
                <tr key={i}>
                  <td className="mono">{rule.manager ?? 'любой'}</td>
                  <td className="mono">{rule.name}</td>
                  <td className="mono">{rule.versions}</td>
                  <td className="small dim">{rule.reason}</td>
                  <td className="small">
                    {rule.added_by ?? '—'} {rule.added_at ? `· ${rule.added_at}` : ''}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ) : null}

      {policies.data?.licenses ? (
        <div className="card">
          <h2>Справочник лицензий (SPDX)</h2>
          <p className="small dim">
            Файл <code>{policies.data.licenses.path}</code>, загружен{' '}
            {formatTime(policies.data.licenses.loaded_at)}.
          </p>
          <div className="grid cols-2">
            <div>
              <h3>Разрешены</h3>
              <div className="row">
                {(policies.data.licenses.allowed ?? []).map((l: Record<string, string>) => (
                  <span className="badge mono pass" key={l.spdx_id} title={l.notes ?? ''}>
                    {l.spdx_id}
                  </span>
                ))}
              </div>
            </div>
            <div>
              <h3>Запрещены</h3>
              <div className="row">
                {(policies.data.licenses.forbidden ?? []).map((l: Record<string, string>) => (
                  <span className="badge mono fail" key={l.spdx_id} title={l.notes ?? ''}>
                    {l.spdx_id}
                  </span>
                ))}
              </div>
            </div>
          </div>
        </div>
      ) : null}
      </>}
    </>
  )
}

function SettingValue({ row, isAdmin, onSaved, onError }: {
  row: SettingRow
  isAdmin: boolean
  onSaved: (message: string) => void
  onError: (message: string) => void
}) {
  const [value, setValue] = useState(String(row.value ?? ''))
  const [busy, setBusy] = useState(false)

  if (row.secret || !row.editable || !isAdmin) {
    return <td className="mono small"><span className={row.secret ? 'muted' : ''}>{String(row.value ?? '—') || 'пусто'}</span></td>
  }
  return (
    <td className="setting-value">
      <div className="row nowrap">
        <input className="mono" value={value} onChange={(event) => setValue(event.target.value)} />
        <button className="small" disabled={busy || value === String(row.value ?? '')} onClick={() => {
          setBusy(true)
          onError('')
          api.saveSettings({ [row.env]: value })
            .then((result) => onSaved(result.message))
            .catch((exc: Error) => onError(exc.message))
            .finally(() => setBusy(false))
        }}>{busy ? '…' : 'сохранить'}</button>
      </div>
    </td>
  )
}

function UsersPanel() {
  const users = useAsync(() => api.adminUsers(), [])
  const [username, setUsername] = useState('')
  const [email, setEmail] = useState('')
  const [fullName, setFullName] = useState('')
  const [password, setPassword] = useState('')
  const [description, setDescription] = useState('')
  const [isSuperuser, setIsSuperuser] = useState(false)
  const [mustChange, setMustChange] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [message, setMessage] = useState<string | null>(null)

  return (
    <>
      <div className="card">
        <div className="row between">
          <div>
            <h2>Пользователи приложения</h2>
            <p className="page-hint">
              Локальные учётные записи создаёт администратор. OIDC-пользователь появляется
              автоматически после первого подтверждённого входа — заранее создавать его не нужно.
            </p>
          </div>
          <span className="badge info">{users.data?.items.length ?? 0} учётных записей</span>
        </div>
        {message ? <Alert kind="ok">{message}</Alert> : null}
        {error ? <Alert kind="error">{error}</Alert> : null}
        {users.error ? <Alert kind="error">{users.error}</Alert> : null}
        {users.loading ? <Loader /> : null}
        <div className="user-list">
          {(users.data?.items ?? []).map((user) => (
            <UserAccessRow key={user.id} user={user} roles={users.data?.roles ?? []}
              onSaved={() => { setMessage(`Доступ ${user.username} обновлён`); users.reload() }}
              onError={setError} />
          ))}
        </div>
      </div>

      <div className="card">
        <h2>Добавить пользователя</h2>
        <p className="small dim">
          Здесь создаются только локальные пользователи. Пароль хранится как
          Argon2id-хэш, открытое значение после создания получить нельзя.
        </p>
        <div className="grid cols-3">
          <label><span>Логин</span><input className="wide" value={username} onChange={(e) => setUsername(e.target.value)} /></label>
          <label><span>Имя</span><input className="wide" value={fullName} onChange={(e) => setFullName(e.target.value)} /></label>
          <label><span>Email</span><input className="wide" value={email} onChange={(e) => setEmail(e.target.value)} /></label>
          <label><span>Описание</span><input className="wide" value={description} onChange={(e) => setDescription(e.target.value)} /></label>
          <label><span>Начальный пароль</span><input className="wide" type="password" autoComplete="new-password" value={password} onChange={(e) => setPassword(e.target.value)} /></label>
        </div>
        <div className="row" style={{ marginBottom: 12 }}>
          <label className="row"><input type="checkbox" checked={isSuperuser} onChange={(e) => setIsSuperuser(e.target.checked)} /><span>Администратор</span></label>
          <label className="row"><input type="checkbox" checked={mustChange} onChange={(e) => setMustChange(e.target.checked)} /><span>Сменить пароль при первом входе</span></label>
        </div>
        <button className="primary" disabled={!username.trim() || password.length < 6} onClick={() => {
          setError(null)
          api.createAdminUser({
            username: username.trim(),
            email: email.trim(),
            full_name: fullName.trim(),
            description: description.trim(),
            roles: isSuperuser ? ['admin', 'developer'] : ['developer'],
            password,
            is_superuser: isSuperuser,
            must_change_password: mustChange,
          })
            .then(() => {
              setUsername(''); setEmail(''); setFullName(''); setPassword(''); setDescription('')
              setIsSuperuser(false); setMustChange(true)
              setMessage('Локальный пользователь создан')
              users.reload()
            })
            .catch((exc: Error) => setError(exc.message))
        }}>+ Пользователь</button>
      </div>
    </>
  )
}

function UserAccessRow({ user, roles, onSaved, onError }: {
  user: AdminUser
  roles: string[]
  onSaved: () => void
  onError: (message: string) => void
}) {
  const [selected, setSelected] = useState(user.roles)
  const [active, setActive] = useState(user.is_active)
  const [superuser, setSuperuser] = useState(user.is_superuser)
  const [username, setUsername] = useState(user.username)
  const [email, setEmail] = useState(user.email ?? '')
  const [fullName, setFullName] = useState(user.full_name ?? '')
  const [description, setDescription] = useState(user.description ?? '')
  const [password, setPassword] = useState('')
  const [mustChange, setMustChange] = useState(true)
  const [busy, setBusy] = useState(false)
  return (
    <div className="user-row">
      <div className="user-identity">
        <span className="avatar">{user.display_name.slice(0, 2).toUpperCase()}</span>
        <details><summary><strong>{user.display_name}</strong><small>{user.username} · {user.email ?? 'без email'}</small></summary>
          <label><span>Логин</span><input value={username} onChange={(e) => setUsername(e.target.value)} /></label>
          <label><span>Имя</span><input value={fullName} onChange={(e) => setFullName(e.target.value)} /></label>
          <label><span>Email</span><input value={email} onChange={(e) => setEmail(e.target.value)} /></label>
          <label><span>Описание</span><textarea value={description} onChange={(e) => setDescription(e.target.value)} /></label>
        </details>
      </div>
      <span className="badge mono">{user.source}</span>
      <div className="role-checks">
        {roles.filter((role) => role !== 'admin').map((role) => <label key={role} className="row">
          <input type="checkbox" checked={selected.includes(role)} onChange={(event) => {
            setSelected(event.target.checked ? [...selected, role] : selected.filter((item) => item !== role))
          }} /><span>{role}</span>
        </label>)}
      </div>
      <label className="row active-toggle"><input type="checkbox" checked={superuser} onChange={(e) => setSuperuser(e.target.checked)} /><span>администратор</span></label>
      <label className="row active-toggle"><input type="checkbox" checked={active} onChange={(e) => setActive(e.target.checked)} /><span>активен</span></label>
      {user.source === 'local' ? <div>
        <input className="small" type="password" autoComplete="new-password" placeholder="новый пароль" value={password} onChange={(e) => setPassword(e.target.value)} />
        {password ? <label className="row small"><input type="checkbox" checked={mustChange} onChange={(e) => setMustChange(e.target.checked)} /><span>сменить при входе</span></label> : null}
      </div> : null}
      <button className="small" disabled={busy} onClick={() => {
        setBusy(true); onError('')
        api.updateAdminUser(user.id, {
          username, email, full_name: fullName, description,
          roles: selected, is_superuser: superuser, is_active: active,
          ...(password ? { password, must_change_password: mustChange } : {}),
        })
          .then(onSaved).catch((exc: Error) => onError(exc.message)).finally(() => setBusy(false))
      }}>{busy ? '…' : 'сохранить'}</button>
    </div>
  )
}

function OIDCPanel() {
  const settings = useAsync(() => api.oidcSettings(), [])
  const [draft, setDraft] = useState<OIDCSettings | null>(null)
  const [secret, setSecret] = useState('')
  const [message, setMessage] = useState<string | null>(null)
  const [error, setError] = useState<string | null>(null)
  const value = draft ?? settings.data
  if (settings.loading || !value) return <Loader />
  const change = (patch: Partial<OIDCSettings>) => setDraft({ ...value, ...patch })
  return <div className="card">
    <h2>OIDC / Keycloak</h2>
    <p className="page-hint">Настройка применяется сразу, без пересборки и перезапуска. Redirect URI добавьте в клиент Keycloak в точности как показано ниже.</p>
    {message ? <Alert kind="ok">{message}</Alert> : null}
    {error || settings.error ? <Alert kind="error">{error || settings.error}</Alert> : null}
    <label className="row"><input type="checkbox" checked={value.enabled} onChange={(e) => change({ enabled: e.target.checked })} /><span>Включить вход через OIDC</span></label>
    <div className="grid cols-2">
      <label><span>Issuer</span><input className="wide mono" value={value.issuer} onChange={(e) => change({ issuer: e.target.value })} placeholder="https://keycloak.example/realms/company" /></label>
      <label><span>Client ID</span><input className="wide mono" value={value.client_id} onChange={(e) => change({ client_id: e.target.value })} /></label>
      <label><span>Client secret {value.secret_set ? '(уже задан; пусто — не менять)' : ''}</span><input className="wide" type="password" autoComplete="new-password" value={secret} onChange={(e) => setSecret(e.target.value)} /></label>
      <label><span>Публичный адрес сервиса</span><input className="wide mono" value={value.public_base_url} onChange={(e) => change({ public_base_url: e.target.value })} placeholder="https://moderation.example" /></label>
      <label><span>Текст кнопки входа</span><input className="wide" value={value.button_label} onChange={(e) => change({ button_label: e.target.value })} /></label>
      <label><span>Redirect URI</span><input className="wide mono" readOnly value={(value.public_base_url || window.location.origin).replace(/\/$/, '') + '/api/v1/auth/oidc/callback'} /></label>
    </div>
    <button className="primary" onClick={() => {
      setError(null)
      api.saveOidcSettings({ ...value, client_secret: secret }).then(() => {
        setMessage('OIDC-настройки сохранены и уже используются сервисом'); setSecret(''); setDraft(null); settings.reload()
      }).catch((exc: Error) => setError(exc.message))
    }}>Сохранить OIDC</button>
  </div>
}

function QueueCard({
  info,
  isAdmin,
  onDone,
}: {
  info: Record<string, any>
  isAdmin: boolean
  onDone: () => void
}) {
  const [message, setMessage] = useState<string | null>(null)
  const worker = info.worker ?? {}
  const watchdog = info.watchdog ?? {}
  const stuck = Number(info.queue?.stuck_items ?? 0)
  const alive = Boolean(worker.alive)

  return (
    <div className="card">
      <div className="row between">
        <h2>Обработка очереди</h2>
        {isAdmin ? (
          <button
            className="small"
            onClick={() =>
              api
                .sweepQueue()
                .then((res) => {
                  setMessage(
                    `Проход сторожа: зависших — ${res.stuck}, подхвачено — ${res.recovered}` +
                      (res.mode === 'inline' ? ' (выполнено на месте, worker молчит)' : ''),
                  )
                  onDone()
                })
                .catch((exc: Error) => setMessage(exc.message))
            }
          >
            разобрать очередь сейчас
          </button>
        ) : null}
      </div>
      {message ? <Alert kind="info">{message}</Alert> : null}
      {!alive ? (
        <Alert kind="warn">
          Worker очереди не отвечает: {String(worker.detail)}. Пакеты не остановятся — их подхватит
          сторож в процессе API, но проверки будут идти медленнее. Поднимите контейнер{' '}
          <code>worker-go</code>.
        </Alert>
      ) : null}
      {stuck > 0 ? (
        <Alert kind="warn">
          Пакетов, висящих в очереди дольше {String(watchdog.stuck_after_seconds)} с: {stuck}.
          Сторож заберёт их в ближайший проход.
        </Alert>
      ) : null}
      <dl className="kv">
        <dt>Go worker</dt>
        <dd>
          <span className={alive ? 'badge pass' : 'badge fail'}>
            {alive ? 'разбирает очередь' : 'не отвечает'}
          </span>
        </dd>
        <dt>Последний heartbeat</dt>
        <dd>{formatTime((worker.last_seen as string) ?? null)}</dd>
        <dt>Зависших пакетов</dt>
        <dd className="mono">{stuck}</dd>
        <dt>Сторож очереди</dt>
        <dd>
          {watchdog.enabled
            ? `включён, проход раз в ${String(watchdog.interval_seconds)} с`
            : 'выключен (PIPELINE_WATCHDOG_ENABLED=false)'}
        </dd>
      </dl>
    </div>
  )
}

function VulnIndexCard({ info, isSec }: { info: Record<string, unknown>; isSec: boolean }) {
  const [message, setMessage] = useState<string | null>(null)
  const stale = Boolean(info.stale)

  return (
    <div className="card">
      <div className="row between">
        <h2>База уязвимостей OSV</h2>
        {isSec ? (
          <button
            className="small"
            onClick={() =>
              api
                .syncOsv()
                .then((res) => setMessage(`Синхронизация: ${JSON.stringify(res)}`))
                .catch((exc: Error) => setMessage(exc.message))
            }
          >
            синхронизировать снапшот
          </button>
        ) : null}
      </div>
      {message ? <Alert kind="info">{message}</Alert> : null}
      {stale ? (
        <Alert kind="warn">
          Снапшот устарел или не загружен: шаг OSV даст предупреждение, но сам по себе не заблокирует
          публикацию. Песочница остаётся обязательной там, где она применима.
        </Alert>
      ) : null}
      <dl className="kv">
        <dt>Источник</dt>
        <dd className="mono">{String(info.source)}</dd>
        <dt>Версия снапшота</dt>
        <dd className="mono">{String(info.version ?? 'не загружен')}</dd>
        <dt>Дата снапшота</dt>
        <dd>{formatTime((info.published_at as string) ?? null)}</dd>
        <dt>Записей</dt>
        <dd>{String(info.record_count ?? '—')}</dd>
        <dt>Возраст</dt>
        <dd>
          {info.age_days !== null && info.age_days !== undefined
            ? `${Number(info.age_days).toFixed(1)} дн (допустимо ${String(info.max_staleness_days)})`
            : '—'}
        </dd>
      </dl>
    </div>
  )
}
