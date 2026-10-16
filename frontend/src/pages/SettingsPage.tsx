import { useEffect, useState } from 'react'

import { Alert, Loader, formatTime, useAsync } from '../components/ui'
import {
  api,
  type AdminUser,
  type ArtifactCatalogSyncStatus,
  type BlacklistRule,
  type LicensePolicyEntry,
  type Manager,
  type Me,
  type OIDCSettings,
  type SettingRow,
} from '../lib/api'

export default function SettingsPage({ me }: { me: Me }) {
  const settings = useAsync(() => api.settings(), [])
  const policies = useAsync(() => api.policies(), [])
  const system = useAsync(() => api.systemStatus(), [])
  const catalogSync = useAsync(() => api.artifactCatalogSyncStatus(), [])
  const [message, setMessage] = useState<string | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [activeTab, setActiveTab] = useState<'overview' | 'artifact' | 'integrations' | 'policies' | 'users'>('overview')
  const isAdmin = me.roles.includes('admin')
  const canEditLicenses = isAdmin || me.roles.includes('legal')
  const isSec = me.roles.includes('devsecops') || isAdmin

  useEffect(() => {
    const status = catalogSync.data?.last_run?.status
    if (status !== 'queued' && status !== 'running') return
    const timer = window.setInterval(() => catalogSync.reload(), 5000)
    return () => window.clearInterval(timer)
  }, [catalogSync.data?.last_run?.status])

  const sections = new Map<string, SettingRow[]>()
  for (const row of settings.data ?? []) {
    const list = sections.get(row.section) ?? []
    list.push(row)
    sections.set(row.section, list)
  }

  const settingsSections = (names: string[]) => names.map((section) => {
    const rows = sections.get(section)
    if (!rows?.length) return null
    return <div className="card" key={section}>
      <h2>{section}</h2>
      <div className="table-scroll"><table>
        <thead><tr><th>Переменная</th><th>Значение</th><th>Описание</th></tr></thead>
        <tbody>{rows.map((row) => <tr key={row.env}>
          <td className="mono nowrap">{row.env}</td>
          <SettingValue row={row} isAdmin={isAdmin} onSaved={(text) => {
            setMessage(text); settings.reload()
          }} onError={setError} />
          <td className="small dim">{row.description}</td>
        </tr>)}</tbody>
      </table></div>
    </div>
  })

  return (
    <>
      <div className="topbar">
        <div>
          <h1>Настройка</h1>
          <p className="page-hint">
            Общие адреса и пороги можно сохранить здесь. Процессы автоматически
            перечитают сохранённую конфигурацию — ручной перезапуск и пересборка не нужны.
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
        <button className={activeTab === 'overview' ? 'active' : ''} onClick={() => setActiveTab('overview')}>Сервис</button>
        <button className={activeTab === 'artifact' ? 'active' : ''} onClick={() => setActiveTab('artifact')}>Артефактори</button>
        <button className={activeTab === 'integrations' ? 'active' : ''} onClick={() => setActiveTab('integrations')}>Интеграции</button>
        <button className={activeTab === 'policies' ? 'active' : ''} onClick={() => setActiveTab('policies')}>Политики</button>
        {isAdmin ? (
          <button className={activeTab === 'users' ? 'active' : ''} onClick={() => setActiveTab('users')}>
            Пользователи и роли
          </button>
        ) : null}
      </div>

      {message ? <Alert kind="ok">{message}</Alert> : null}
      {error ? <Alert kind="error">{error}</Alert> : null}
      {settings.error ? <Alert kind="error">{settings.error}</Alert> : null}
      {settings.loading ? <Loader /> : null}

      {activeTab === 'users' && isAdmin ? <UsersPanel /> : null}

      {activeTab === 'overview' && system.data ? <QueueCard info={system.data} isAdmin={isAdmin} onDone={() => system.reload()} /> : null}
      {activeTab === 'overview' ? settingsSections(['Общие', 'Пороги', 'Лимиты', 'Надёжность']) : null}

      {activeTab === 'artifact' && catalogSync.data ? (
        <ArtifactCatalogSyncCard
          info={catalogSync.data}
          isAdmin={isAdmin}
          onDone={() => catalogSync.reload()}
        />
      ) : null}
      {activeTab === 'artifact' ? settingsSections(['Артефактори']) : null}

      {activeTab === 'integrations' && isAdmin ? <OIDCPanel /> : null}
      {activeTab === 'integrations' ? settingsSections(['Песочница', 'Dragon', 'GitLab', 'Доступ']) : null}

      {activeTab === 'policies' && policies.data?.vuln_index ? <VulnIndexCard info={policies.data.vuln_index} isSec={isSec} /> : null}
      {activeTab === 'policies' ? settingsSections(['Уязвимости', 'Политики']) : null}

      {activeTab === 'policies' && policies.data?.blacklist ? (
        <div className="card">
          <div className="row between">
            <div>
              <h2>Blacklist</h2>
              <p className="small dim">
                Применён {formatTime(policies.data.blacklist.loaded_at)}. Совпадение останавливает конвейер
                на шаге 1 — пакет не скачивается.
              </p>
            </div>
            <span className="badge info">
              {(policies.data.blacklist.rules ?? []).length} правил
            </span>
          </div>
          {policies.data.blacklist.error ? (
            <Alert kind="warn">Политика не загружена: {policies.data.blacklist.error}</Alert>
          ) : null}
          <BlacklistEditor
            initialRules={policies.data.blacklist.rules ?? []}
            isAdmin={isAdmin}
            onSaved={(text) => { setMessage(text); policies.reload() }}
          />
        </div>
      ) : null}

      {activeTab === 'policies' && policies.data?.licenses ? (
        <div className="card">
          <LicensePolicyEditor
            allowed={policies.data.licenses.allowed ?? []}
            forbidden={policies.data.licenses.forbidden ?? []}
            loadedAt={policies.data.licenses.loaded_at}
            editable={canEditLicenses}
            onSaved={(text) => { setMessage(text); policies.reload() }}
          />
        </div>
      ) : null}
    </>
  )
}

function LicensePolicyEditor({ allowed, forbidden, loadedAt, editable, onSaved }: {
  allowed: LicensePolicyEntry[]
  forbidden: LicensePolicyEntry[]
  loadedAt: string
  editable: boolean
  onSaved: (message: string) => void
}) {
  const [entries, setEntries] = useState<LicensePolicyEntry[]>([...allowed, ...forbidden])
  const [filter, setFilter] = useState('')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)
  useEffect(() => setEntries([...allowed, ...forbidden]), [allowed, forbidden])
  const needle = filter.trim().toLowerCase()
  const visible = entries.map((entry, index) => ({ entry, index })).filter(({ entry }) =>
    !needle || [entry.spdx_id, entry.name, entry.notes].some((value) =>
      String(value ?? '').toLowerCase().includes(needle)),
  )
  const change = (index: number, patch: Partial<LicensePolicyEntry>) =>
    setEntries((current) => current.map((entry, i) => i === index ? { ...entry, ...patch } : entry))
  return <>
    <div className="row between">
      <div>
        <h2>Политика лицензий (SPDX)</h2>
        <p className="small dim">Применена {formatTime(loadedAt)}</p>
      </div>
      <span className="badge info">{allowed.length} разрешено · {forbidden.length} запрещено</span>
    </div>
    {error ? <Alert kind="error">{error}</Alert> : null}
    <div className="row" style={{ marginBottom: 10 }}>
      <input className="wide" value={filter} onChange={(event) => setFilter(event.target.value)}
        placeholder="Фильтр по SPDX ID, названию или примечанию" />
      {editable ? <button className="small" onClick={() => setEntries((current) => [...current, {
        spdx_id: '', name: '', url: '', notes: '', allowed: true,
      }])}>+ лицензия</button> : null}
    </div>
    <div className="table-scroll policy-table-wrap">
      <table>
        <thead><tr><th>SPDX ID</th><th>Название</th><th>Решение</th><th>Примечание</th>{editable ? <th /> : null}</tr></thead>
        <tbody>{visible.map(({ entry, index }) => <tr key={`${entry.spdx_id}-${index}`}>
          <td>{editable ? <input className="mono" value={entry.spdx_id} onChange={(e) => change(index, { spdx_id: e.target.value })} /> : <span className="mono">{entry.spdx_id}</span>}</td>
          <td>{editable ? <input value={entry.name ?? ''} onChange={(e) => change(index, { name: e.target.value })} /> : (entry.name || '—')}</td>
          <td>{editable ? <select value={entry.allowed ? 'allow' : 'deny'} onChange={(e) => change(index, { allowed: e.target.value === 'allow' })}>
            <option value="allow">разрешена</option><option value="deny">запрещена</option>
          </select> : <span className={`badge ${entry.allowed ? 'pass' : 'fail'}`}>{entry.allowed ? 'разрешена' : 'запрещена'}</span>}</td>
          <td>{editable ? <input value={entry.notes ?? ''} onChange={(e) => change(index, { notes: e.target.value })} /> : (entry.notes || '—')}</td>
          {editable ? <td><button className="small danger" onClick={() => setEntries((current) => current.filter((_, i) => i !== index))}>удалить</button></td> : null}
        </tr>)}</tbody>
      </table>
    </div>
    {editable ? <button className="primary" disabled={busy || entries.some((entry) => !entry.spdx_id.trim())}
      onClick={() => {
        setBusy(true); setError(null)
        api.saveLicensePolicy(entries).then((result) => onSaved(result.message))
          .catch((exc: Error) => setError(exc.message)).finally(() => setBusy(false))
      }}>{busy ? 'Сохранение…' : 'Сохранить политику лицензий'}</button> : null}
  </>
}

function ArtifactCatalogSyncCard({
  info,
  isAdmin,
  onDone,
}: {
  info: ArtifactCatalogSyncStatus
  isAdmin: boolean
  onDone: () => void
}) {
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [selectedManagers, setSelectedManagers] = useState<string[]>(info.managers)
  useEffect(() => setSelectedManagers(info.managers), [info.managers.join(',')])
  const run = info.last_run
  const managerDetails = Object.values(run?.details?.managers ?? {})
  const physicalFiles = managerDetails.reduce((total, detail) => total + (detail.files ?? 0), 0)
  const recognizedArtifacts = managerDetails.reduce((total, detail) => total + (detail.parsed ?? 0), 0)
  const statusTitle: Record<string, string> = {
    queued: 'ожидает worker', running: 'выполняется', succeeded: 'завершена', failed: 'ошибка',
  }
  return (
    <div className="card">
      <div className="row between">
        <div>
          <h2>Синхронизация базы пакетов</h2>
          <p className="small dim">
            Доверенные moderated-репозитории: {info.managers.length ? info.managers.join(', ') : 'не выбраны'}.
            Найденные пакеты сразу появляются в web-базе без повторной модерации.
          </p>
          {isAdmin ? <div className="row" style={{ marginTop: 8 }}>
            {(info.available_managers ?? info.managers).map((manager) => <label className="row" style={{ margin: 0 }} key={manager}>
              <input type="checkbox" checked={selectedManagers.includes(manager)} onChange={(event) =>
                setSelectedManagers((current) => event.target.checked
                  ? [...current, manager]
                  : current.filter((value) => value !== manager))} />
              <span className="mono">{manager}</span>
            </label>)}
          </div> : null}
        </div>
        {isAdmin ? (
          <button
            className="small"
            disabled={busy || !info.maintenance_enabled || selectedManagers.length === 0 || run?.status === 'running' || run?.status === 'queued'}
            onClick={() => {
              setBusy(true); setError(null)
              api.startArtifactCatalogSync(selectedManagers)
                .then(() => onDone())
                .catch((exc: Error) => setError(exc.message))
                .finally(() => setBusy(false))
            }}
          >
            {busy ? 'запускаю…' : 'синхронизировать сейчас'}
          </button>
        ) : null}
      </div>
      {error ? <Alert kind="error">{error}</Alert> : null}
      {!info.maintenance_enabled ? (
        <Alert kind="warn">Включите MAINTENANCE_ENABLED: фоновую синхронизацию выполняет worker.</Alert>
      ) : selectedManagers.length === 0 ? (
        <Alert kind="warn">Выберите хотя бы один пакетный менеджер для синхронизации.</Alert>
      ) : run ? (
        <div className="grid cols-2">
          <dl>
            <dt>Последний запуск</dt><dd>#{run.id} — {statusTitle[run.status] ?? run.status}</dd>
            <dt>Источник</dt><dd>{run.trigger}</dd>
            <dt>Начат</dt><dd>{formatTime(run.started_at ?? run.created_at)}</dd>
            <dt>Завершён</dt><dd>{formatTime(run.finished_at ?? null)}</dd>
          </dl>
          <dl>
            <dt>Файлов в артефактори</dt><dd>{physicalFiles || run.discovered + run.skipped}</dd>
            <dt>Распознано артефактов</dt><dd>{recognizedArtifacts || run.discovered}</dd>
            <dt>Добавлено версий</dt><dd>{run.imported}</dd>
            <dt>Обновлено версий</dt><dd>{run.updated}</dd>
            <dt>Служебных/нераспознанных файлов</dt><dd>{run.skipped}</dd>
            <dt>Ошибок</dt><dd>{run.errors}</dd>
          </dl>
          {run.error ? <Alert kind="error">{run.error}</Alert> : null}
        </div>
      ) : (
        <p className="small dim">Синхронизация ещё не запускалась.</p>
      )}
    </div>
  )
}

const BLACKLIST_MANAGERS: Array<{ code: Manager | ''; title: string }> = [
  { code: '', title: 'Любой менеджер' },
  { code: 'pypi', title: 'PyPI' },
  { code: 'npm', title: 'npm' },
  { code: 'go', title: 'Go modules' },
  { code: 'nuget', title: 'NuGet' },
  { code: 'conan', title: 'Conan' },
  { code: 'docker', title: 'Docker' },
  { code: 'luarocks', title: 'LuaRocks' },
  { code: 'maven', title: 'Maven' },
  { code: 'php', title: 'Composer / PHP' },
  { code: 'terraform', title: 'Terraform' },
  { code: 'git', title: 'Git' },
  { code: 'files', title: 'Файлы' },
]

function BlacklistEditor({ initialRules, isAdmin, onSaved }: {
  initialRules: BlacklistRule[]
  isAdmin: boolean
  onSaved: (message: string) => void
}) {
  const [rules, setRules] = useState<BlacklistRule[]>(initialRules)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [filter, setFilter] = useState('')

  useEffect(() => setRules(initialRules), [initialRules])

  const change = (index: number, patch: Partial<BlacklistRule>) => {
    setRules((current) => current.map((rule, i) => i === index ? { ...rule, ...patch } : rule))
  }
  const add = () => setRules((current) => [...current, {
    manager: '', name: '', versions: '*', reason: '', added_by: '', added_at: '',
  }])
  const needle = filter.trim().toLowerCase()
  const visibleRules = rules.map((rule, index) => ({ rule, index })).filter(({ rule }) =>
    !needle || [rule.manager, rule.name, rule.versions, rule.reason, rule.added_by]
      .some((value) => String(value ?? '').toLowerCase().includes(needle)),
  )

  return <>
    {error ? <Alert kind="error">{error}</Alert> : null}
    {rules.length === 0 ? (
      <Alert kind="info">Blacklist пуст: ни один пакет не запрещён правилами.</Alert>
    ) : null}
    <div className="row" style={{ marginBottom: 10 }}>
      <input className="wide" value={filter} onChange={(event) => setFilter(event.target.value)}
        placeholder="Фильтр по менеджеру, пакету, версии, причине или автору" />
      <span className="small muted">Показано {visibleRules.length} из {rules.length}</span>
    </div>
    <div className="blacklist-table-wrap">
      <table className={isAdmin ? 'blacklist-editor' : ''}>
        <thead>
          <tr>
            <th>Менеджер</th>
            <th>Имя / glob</th>
            <th>Версии</th>
            <th>Причина</th>
            <th>Добавил</th>
            {isAdmin ? <th aria-label="Действия" /> : null}
          </tr>
        </thead>
        <tbody>
          {visibleRules.map(({ rule, index }) => (
            <tr key={index}>
              <td>{isAdmin ? (
                <select className="wide" aria-label={`Менеджер правила ${index + 1}`}
                  value={rule.manager} onChange={(event) => change(index, { manager: event.target.value as Manager | '' })}>
                  {BLACKLIST_MANAGERS.map((manager) => (
                    <option value={manager.code} key={manager.code || 'any'}>{manager.title}</option>
                  ))}
                </select>
              ) : <span className="mono">{rule.manager || 'любой'}</span>}</td>
              <td>{isAdmin ? (
                <input className="wide mono" aria-label={`Имя правила ${index + 1}`}
                  placeholder="package или glob-*" value={rule.name}
                  onChange={(event) => change(index, { name: event.target.value })} />
              ) : <span className="mono">{rule.name}</span>}</td>
              <td>{isAdmin ? (
                <input className="wide mono" aria-label={`Версии правила ${index + 1}`}
                  placeholder="* или >=1.0,<2.0" value={rule.versions}
                  onChange={(event) => change(index, { versions: event.target.value })} />
              ) : <span className="mono">{rule.versions}</span>}</td>
              <td>{isAdmin ? (
                <input className="wide" aria-label={`Причина правила ${index + 1}`}
                  placeholder="Почему пакет запрещён" value={rule.reason}
                  onChange={(event) => change(index, { reason: event.target.value })} />
              ) : <span className="small dim">{rule.reason}</span>}</td>
              <td className="small nowrap">
                {rule.added_by || '—'} {rule.added_at ? `· ${rule.added_at}` : ''}
              </td>
              {isAdmin ? <td>
                <button className="small danger" disabled={busy}
                  aria-label={`Удалить правило ${index + 1}`}
                  onClick={() => setRules((current) => current.filter((_, i) => i !== index))}>
                  удалить
                </button>
              </td> : null}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
    {isAdmin ? <div className="row blacklist-actions">
      <button className="small" disabled={busy} onClick={add}>+ правило</button>
      <button className="primary" disabled={busy || rules.some((rule) => !rule.name.trim())}
        onClick={() => {
          setBusy(true); setError(null)
          api.saveBlacklist(rules)
            .then((result) => { setRules(result.rules); onSaved(result.message) })
            .catch((exc: Error) => setError(exc.message))
            .finally(() => setBusy(false))
        }}>
        {busy ? 'Сохранение…' : 'Сохранить blacklist'}
      </button>
    </div> : null}
  </>
}

function SettingValue({ row, isAdmin, onSaved, onError }: {
  row: SettingRow
  isAdmin: boolean
  onSaved: (message: string) => void
  onError: (message: string) => void
}) {
  const [value, setValue] = useState(row.secret ? '' : String(row.value ?? ''))
  const [busy, setBusy] = useState(false)

  if (!row.editable || !isAdmin) {
    return <td className="mono small"><span className={row.secret ? 'muted' : ''}>{String(row.value ?? '—') || 'пусто'}</span></td>
  }
  return (
    <td className="setting-value">
      <div className="row nowrap">
        <input className="mono" type={row.secret ? 'password' : 'text'}
          autoComplete={row.secret ? 'new-password' : undefined}
          placeholder={row.secret ? String(row.value ?? '') : ''}
          aria-label={row.secret
            ? (String(row.value ?? '') ? `${row.env}: секрет задан, введите новый для замены` : `${row.env}: секрет не задан`)
            : row.env}
          value={value} onChange={(event) => setValue(event.target.value)} />
        <button className="small" disabled={busy || (!row.secret && value === String(row.value ?? '')) || (row.secret && !value)} onClick={() => {
          setBusy(true)
          onError('')
          api.saveSettings({ [row.env]: value })
            .then((result) => {
              if (row.secret) setValue('')
              onSaved(result.message)
            })
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
              onDeleted={() => { setMessage(`Пользователь ${user.username} удалён`); users.reload() }}
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

function UserAccessRow({ user, roles, onSaved, onDeleted, onError }: {
  user: AdminUser
  roles: string[]
  onSaved: () => void
  onDeleted: () => void
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
      <button className="small danger" disabled={busy} onClick={() => {
        if (!window.confirm(`Удалить пользователя ${user.username}? История его действий сохранится.`)) return
        setBusy(true); onError('')
        api.deleteAdminUser(user.id)
          .then(onDeleted).catch((exc: Error) => onError(exc.message)).finally(() => setBusy(false))
      }}>удалить</button>
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
      <label><span>Client secret</span><input className="wide mono" type="password" autoComplete="new-password"
        placeholder={value.secret_mask ?? ''}
        aria-label={value.secret_set ? 'Client secret задан, введите новый для замены' : 'Client secret не задан'}
        value={secret} onChange={(e) => setSecret(e.target.value)} /></label>
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
  // Backend намеренно не притворяется heartbeat'ом контейнера: он показывает
  // наблюдаемый результат — есть ли пакеты, которые никто не забирает.
  const queueIsMoving = worker.queue_is_moving !== false

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
                  setMessage(`Проход сторожа завершён: обработано пакетов — ${Number(res.processed ?? 0)}`)
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
      {!queueIsMoving && stuck > 0 ? (
        <Alert kind="warn">
          Очередь не разбирается: пакеты лежат дольше установленного порога. Проверьте контейнер{' '}
          <code>worker-go</code> или запустите ручной проход сторожа.
        </Alert>
      ) : null}
      {stuck > 0 ? (
        <Alert kind="warn">
          Пакетов, висящих в очереди дольше {String(watchdog.stuck_after_seconds)} с: {stuck}.
          Сторож заберёт их в ближайший проход.
        </Alert>
      ) : null}
      <dl className="kv">
        <dt>Состояние очереди</dt>
        <dd>
          <span className={queueIsMoving ? 'badge pass' : 'badge fail'}>
            {queueIsMoving ? 'залежавшихся пакетов нет' : 'очередь не разбирается'}
          </span>
        </dd>
        <dt>Как определяется</dt>
        <dd className="small muted">{String(worker.note ?? 'По возрасту пакетов в очереди')}</dd>
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
