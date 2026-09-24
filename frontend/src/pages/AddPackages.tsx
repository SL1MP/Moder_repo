import { useMemo, useState } from 'react'
import { Link } from 'react-router-dom'

import { Alert, Badge, Copyable, DependencyTreeView, Empty, Loader, useAsync } from '../components/ui'
import {
  api,
  type AuthConfig,
  type CreateRequestResult,
  type DependencyTree,
  type Manager,
  type Me,
  type ParsedPackage,
} from '../lib/api'

type Mode = 'check' | 'list' | 'file' | 'gitlab'

// Порядок вкладок — поиск первым: сначала проверяем, нет ли пакета уже в базе,
// и только если не нашли — заводим заявку одним из трёх способов
// (docs/flows.md, "Что стоит пересмотреть" → зафиксировано как решение).
const MODES: { key: Mode; title: string; hint: string }[] = [
  { key: 'check', title: 'Найти пакет', hint: 'сначала проверьте — вдруг уже есть' },
  { key: 'list', title: 'Список пакетов', hint: 'по одной записи в строке' },
  { key: 'file', title: 'Файл зависимостей', hint: 'requirements.txt, package-lock.json, go.mod…' },
  { key: 'gitlab', title: 'Ссылка на GitLab', hint: 'файл из приватного проекта' },
]

export default function AddPackages({ me, config }: { me: Me; config: AuthConfig }) {
  const [mode, setMode] = useState<Mode>('check')
  const managers = useAsync(() => api.managers(), [])
  const [manager, setManager] = useState<Manager>('pypi')
  const current = managers.data?.find((m) => m.code === manager)
  // Мостик «не нашли → добавить»: ByCheck кладёт сюда ненайденные записи,
  // ByList подхватывает их как черновик заявки при переключении вкладки.
  const [draft, setDraft] = useState('')

  return (
    <>
      <div className="topbar">
        <div>
          <h1>Пакеты</h1>
          <p className="page-hint">
            Сервис — единственный вход: сначала ищем в базе, заводим заявку только если пакета
            ещё нет. Конвейер проверок запускается автоматически. Транзитивные зависимости
            подтягиваются по галочке — каждая проходит модерацию как отдельный пакет.
          </p>
        </div>
        <div className="who">{me.display_name}</div>
      </div>

      <div className="card tight">
        <div className="row">
          <label style={{ margin: 0 }}>
            <span>Пакетный менеджер</span>
            <select value={manager} onChange={(e) => setManager(e.target.value as Manager)}>
              {(managers.data ?? []).map((m) => (
                <option key={m.code} value={m.code}>
                  {m.title}
                </option>
              ))}
            </select>
          </label>
          {current ? (
            <div className="small dim" style={{ marginTop: 14 }}>
              формат записи: <code>{current.entry_format}</code> · файлы:{' '}
              <code>{(current.dependency_files ?? []).join(', ') || 'не применимо'}</code> · экосистема
              OSV: <code>{current.osv_ecosystem || 'не применимо'}</code>
            </div>
          ) : null}
        </div>
      </div>

      <div className="pill-tabs">
        {MODES.map((m) => (
          <button
            key={m.key}
            className={mode === m.key ? 'active' : ''}
            onClick={() => setMode(m.key)}
            title={m.hint}
          >
            {m.title}
          </button>
        ))}
      </div>

      {mode === 'check' ? (
        <ByCheck
          manager={manager}
          onNotFound={(raw) => {
            setDraft(raw.join('\n'))
            setMode('list')
          }}
        />
      ) : null}
      {mode === 'list' ? (
        <ByList manager={manager} format={current?.entry_format ?? ''} initialText={draft} />
      ) : null}
      {mode === 'file' ? <ByFile manager={manager} files={current?.dependency_files ?? []} /> : null}
      {mode === 'gitlab' ? <ByGitlab manager={manager} config={config} /> : null}
    </>
  )
}

// --------------------------------------------------------------------------- способ 1
function ByList({
  manager,
  format,
  initialText,
}: {
  manager: Manager
  format: string
  initialText?: string
}) {
  const [text, setText] = useState(initialText ?? '')
  const [reason, setReason] = useState('')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [result, setResult] = useState<CreateRequestResult | null>(null)
  const [includeTransitive, setIncludeTransitive] = useState(false)
  const [depth, setDepth] = useState(2)
  const [tree, setTree] = useState<DependencyTree | null>(null)
  const [previewBusy, setPreviewBusy] = useState(false)

  const entries = useMemo(
    () => text.split('\n').map((line) => line.trim()).filter(Boolean),
    [text],
  )

  return (
    <>
      <div className="card">
        <h2>Перечисление пакетов</h2>
        <p className="small dim">
          По одной записи в строке в формате <code>{format}</code>. Уже одобренные в заявку не
          попадут — сервис отдаст ссылку и команду установки.
        </p>
        <label>
          <span>Пакеты ({entries.length})</span>
          <textarea
            value={text}
            onChange={(e) => setText(e.target.value)}
            placeholder={manager === 'pypi' ? 'requests==2.31.0\npydantic==2.6.4' : format}
            style={{ minHeight: 130, fontFamily: 'var(--mono)' }}
          />
        </label>
        <label>
          <span>Обоснование (зачем нужен пакет)</span>
          <input
            className="wide"
            value={reason}
            onChange={(e) => setReason(e.target.value)}
            placeholder="Сервис выставления счетов, спринт 41"
          />
        </label>
        <div className="row" style={{ gap: 12, alignItems: 'baseline' }}>
          <label className="row" style={{ gap: 6, margin: 0 }}>
            <input
              type="checkbox"
              checked={includeTransitive}
              onChange={(e) => {
                setIncludeTransitive(e.target.checked)
                if (!e.target.checked) setTree(null)
              }}
              style={{ width: 'auto' }}
            />
            <span style={{ margin: 0 }}>Раскрыть транзитивные зависимости</span>
          </label>
          {includeTransitive ? (
            <label className="row" style={{ gap: 6, margin: 0 }}>
              <span style={{ margin: 0 }}>Глубина</span>
              <select
                value={depth}
                onChange={(e) => setDepth(Number(e.target.value))}
                style={{ width: 'auto' }}
              >
                <option value={1}>1 — только прямые</option>
                <option value={2}>2</option>
                <option value={3}>3</option>
              </select>
            </label>
          ) : null}
        </div>
        {includeTransitive ? (
          <p className="small dim">
            Каждая найденная зависимость становится отдельным пакетом заявки и проходит те же
            проверки. Посмотрите дерево заранее: один пакет легко тянет за собой полсотни.
          </p>
        ) : null}
        {error ? <Alert kind="error">{error}</Alert> : null}
        <div className="row" style={{ gap: 8 }}>
          <button
            className="primary"
            disabled={busy || !entries.length}
            onClick={() => {
              setBusy(true)
              setError(null)
              api
                .createRequest({
                  manager,
                  packages: entries,
                  reason: reason || undefined,
                  include_transitive: includeTransitive,
                  resolve_depth: includeTransitive ? depth : undefined,
                })
                .then(setResult)
                .catch((exc: Error) => setError(exc.message))
                .finally(() => setBusy(false))
            }}
          >
            {busy ? 'Отправляем…' : 'Отправить на модерацию'}
          </button>
          {includeTransitive ? (
            <button
              disabled={previewBusy || !entries.length}
              onClick={() => {
                setPreviewBusy(true)
                setError(null)
                api
                  .resolveDependencies({ manager, packages: entries, depth })
                  .then(setTree)
                  .catch((exc: Error) => setError(exc.message))
                  .finally(() => setPreviewBusy(false))
              }}
            >
              {previewBusy ? 'Считаем дерево…' : 'Показать дерево'}
            </button>
          ) : null}
        </div>
      </div>
      {tree && !result ? <DependencyTreeView tree={tree} /> : null}
      {result ? <ParseResult result={result} /> : null}
    </>
  )
}

// --------------------------------------------------------------------------- способ 2
function ByFile({ manager, files }: { manager: Manager; files: string[] }) {
  const [file, setFile] = useState<File | null>(null)
  const [reason, setReason] = useState('')
  const [includeTransitive, setIncludeTransitive] = useState(false)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [result, setResult] = useState<CreateRequestResult | null>(null)

  return (
    <>
      <div className="card">
        <h2>Файл с зависимостями</h2>
        <p className="small dim">
          Поддерживаются: <code>{files.join(', ')}</code>. Парсер различает прямые и транзитивные
          зависимости.
        </p>
        <Alert kind="warn">
          Транзитивные зависимости автоматически не подтягиваются: проверяется и публикуется только
          сам заявленный пакет. Если транзитивные нужны — заведите их явно.
        </Alert>
        <label>
          <span>Файл</span>
          <input type="file" onChange={(e) => setFile(e.target.files?.[0] ?? null)} />
        </label>
        <label className="row" style={{ gap: 6 }}>
          <input
            type="checkbox"
            checked={includeTransitive}
            onChange={(e) => setIncludeTransitive(e.target.checked)}
            style={{ width: 'auto' }}
          />
          <span style={{ margin: 0 }}>Заводить и транзитивные зависимости тоже</span>
        </label>
        <label>
          <span>Обоснование</span>
          <input className="wide" value={reason} onChange={(e) => setReason(e.target.value)} />
        </label>
        {error ? <Alert kind="error">{error}</Alert> : null}
        <button
          className="primary"
          disabled={busy || !file}
          onClick={() => {
            if (!file) return
            const form = new FormData()
            form.set('manager', manager)
            form.set('file', file)
            form.set('include_transitive', String(includeTransitive))
            if (reason) form.set('reason', reason)
            setBusy(true)
            setError(null)
            api
              .createRequestFromFile(form)
              .then(setResult)
              .catch((exc: Error) => setError(exc.message))
              .finally(() => setBusy(false))
          }}
        >
          {busy ? 'Разбираем файл…' : 'Разобрать и отправить'}
        </button>
      </div>
      {result ? <ParseResult result={result} /> : null}
    </>
  )
}

// --------------------------------------------------------------------------- способ 3
function ByGitlab({ manager, config }: { manager: Manager; config: AuthConfig }) {
  const status = useAsync(() => api.gitlabStatus(), [])
  const [project, setProject] = useState('')
  const [path, setPath] = useState('')
  const [ref, setRef] = useState('main')
  const [reason, setReason] = useState('')
  const [includeTransitive, setIncludeTransitive] = useState(false)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [result, setResult] = useState<CreateRequestResult | null>(null)

  if (!config.gitlab_enabled) {
    return (
      <Alert kind="info">
        Интеграция с GitLab не настроена. Задайте <code>GITLAB_URL</code>,{' '}
        <code>GITLAB_OAUTH_CLIENT_ID</code> и <code>GITLAB_OAUTH_CLIENT_SECRET</code> в{' '}
        <code>.env</code>.
      </Alert>
    )
  }
  if (status.loading) return <Loader />
  if (!status.data?.connected) {
    return (
      <Alert kind="warn">
        GitLab не подключён. Откройте <Link to="/profile">профиль</Link> и подключите GitLab
        (доступ только на чтение, scope <code>read_repository</code>).
      </Alert>
    )
  }

  return (
    <>
      <div className="card">
        <h2>Файл зависимостей из GitLab</h2>
        <p className="small dim">
          Файл читается от вашего имени, только чтение: ничего не коммитим и merge request'ы не
          открываем.
        </p>
        <div className="grid cols-3">
          <label>
            <span>Проект (ID или group/name)</span>
            <input className="wide" value={project} onChange={(e) => setProject(e.target.value)} />
          </label>
          <label>
            <span>Путь к файлу</span>
            <input
              className="wide"
              value={path}
              onChange={(e) => setPath(e.target.value)}
              placeholder="requirements.txt"
            />
          </label>
          <label>
            <span>Ветка, тег или commit sha</span>
            <input className="wide" value={ref} onChange={(e) => setRef(e.target.value)} />
          </label>
        </div>
        <label className="row" style={{ gap: 6 }}>
          <input
            type="checkbox"
            checked={includeTransitive}
            onChange={(e) => setIncludeTransitive(e.target.checked)}
            style={{ width: 'auto' }}
          />
          <span style={{ margin: 0 }}>Заводить и транзитивные зависимости</span>
        </label>
        <label>
          <span>Обоснование</span>
          <input className="wide" value={reason} onChange={(e) => setReason(e.target.value)} />
        </label>
        {error ? <Alert kind="error">{error}</Alert> : null}
        <button
          className="primary"
          disabled={busy || !project || !path}
          onClick={() => {
            setBusy(true)
            setError(null)
            api
              .createRequestFromGitlab({
                project,
                path,
                ref: ref || 'HEAD',
                manager,
                reason: reason || undefined,
                include_transitive: includeTransitive,
              })
              .then(setResult)
              .catch((exc: Error) => setError(exc.message))
              .finally(() => setBusy(false))
          }}
        >
          {busy ? 'Читаем файл…' : 'Прочитать и отправить'}
        </button>
      </div>
      {result ? <ParseResult result={result} /> : null}
    </>
  )
}

// --------------------------------------------------------------------------- способ 0 (стартовый)
function ByCheck({
  manager,
  onNotFound,
}: {
  manager: Manager
  onNotFound: (raw: string[]) => void
}) {
  const [text, setText] = useState('')
  const [rows, setRows] = useState<Record<string, unknown>[] | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [busy, setBusy] = useState(false)

  const missing = (rows ?? []).filter((r) => r.state === 'not_found').map((r) => String(r.raw))

  return (
    <div className="card">
      <h2>Найти пакет</h2>
      <p className="small dim">
        Сначала проверьте базу — без создания заявки. Если пакета нет, отсюда же можно сразу
        перейти к добавлению.
      </p>
      <label>
        <span>Пакеты</span>
        <textarea
          value={text}
          onChange={(e) => setText(e.target.value)}
          placeholder={manager === 'pypi' ? 'requests==2.31.0\npydantic==2.6.4' : undefined}
          style={{ minHeight: 100, fontFamily: 'var(--mono)' }}
        />
      </label>
      {error ? <Alert kind="error">{error}</Alert> : null}
      <button
        className="primary"
        disabled={busy || !text.trim()}
        onClick={() => {
          setBusy(true)
          setError(null)
          api
            .checkPackages(
              manager,
              text.split('\n').map((l) => l.trim()).filter(Boolean),
            )
            .then((resp) => setRows(resp.packages))
            .catch((exc: Error) => setError(exc.message))
            .finally(() => setBusy(false))
        }}
      >
        {busy ? 'Проверяем…' : 'Проверить'}
      </button>

      {rows ? (
        <>
          <table style={{ marginTop: 12 }}>
            <thead>
              <tr>
                <th>Запись</th>
                <th>Можно ставить?</th>
                <th>Статус</th>
                <th>Что это значит</th>
              </tr>
            </thead>
            <tbody>
              {rows.map((row, i) => (
                <tr key={i}>
                  <td className="mono">{String(row.raw)}</td>
                  <td className="nowrap">{checkVerdict(row)}</td>
                  <td>{row.status ? <Badge value={String(row.status)} /> : '—'}</td>
                  <td className="small dim">
                    {String(row.message ?? '')}
                    {row.install_command ? (
                      <div style={{ marginTop: 4 }}>
                        <Copyable command={String(row.install_command)} />
                      </div>
                    ) : null}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
          {missing.length ? (
            <div className="row" style={{ marginTop: 10 }}>
              <span className="small dim">
                Не найдено в базе: {missing.length} из {rows.length}.
              </span>
              <button className="primary small nowrap" onClick={() => onNotFound(missing)}>
                добавить {missing.length === rows.length ? 'всё' : 'ненайденное'} в заявку →
              </button>
            </div>
          ) : null}
        </>
      ) : null}
    </div>
  )
}

/** Вердикт проверки по базе. Наличие записи ≠ можно ставить: строка появляется
 *  ещё до прохождения конвейера, поэтому состояния разделены по существу. */
function checkVerdict(row: Record<string, unknown>) {
  switch (row.state) {
    case 'approved':
      return (
        <Link to={`/packages?q=${encodeURIComponent(String(row.name ?? ''))}`}>
          <span className="badge approved">можно ставить</span>
        </Link>
      )
    case 'in_progress':
      return row.request_id ? (
        <Link to={`/requests/${row.request_id}`}>
          <span className="badge warn">на модерации</span>
        </Link>
      ) : (
        <span className="badge warn">на модерации</span>
      )
    case 'blocked':
      return <span className="badge fail">нельзя</span>
    case 'not_found':
      return <span className="dim">нет в базе — нужна заявка</span>
    default:
      return <span className="badge fail">формат: {String(row.expected_format ?? '')}</span>
  }
}

// --------------------------------------------------------------------------- результат разбора
function ParseResult({ result }: { result: CreateRequestResult }) {
  const groups: Record<ParsedPackage['state'], ParsedPackage[]> = {
    new: [],
    already_in_base: [],
    invalid_format: [],
  }
  for (const pkg of result.packages) groups[pkg.state].push(pkg)

  return (
    <div className="card">
      <div className="row between">
        <h2>
          Заявка #{result.request_id} · <Badge value={result.status} />
        </h2>
        <Link to={`/requests/${result.request_id}`}>открыть карточку заявки →</Link>
      </div>
      <p className="small dim">
        Принято к проверке: <b>{result.accepted}</b> · уже в базе:{' '}
        <b>{result.skipped_already_in_base}</b> · с ошибкой формата: <b>{result.invalid}</b>
      </p>
      {result.warnings.map((w, i) => (
        <Alert kind="warn" key={i}>
          {w}
        </Alert>
      ))}

      {groups.new.length ? (
        <>
          <h3>Принято к проверке</h3>
          {/* Отступом, а не таблицей: когда в заявке полсотни пакетов,
              единственное, что делает список читаемым, — видно, кто кого
              притащил. */}
          <table>
            <tbody>
              {groups.new.map((p) => (
                <tr key={p.raw}>
                  <td className="mono" style={{ paddingLeft: 4 + (p.depth ?? 0) * 18 }}>
                    {p.depth ? <span className="dep-marker">└ </span> : null}
                    {p.name} {p.version}
                  </td>
                  <td>
                    {p.dependency_kind === 'transitive' ? (
                      <span className="badge">транзитивная</span>
                    ) : (
                      <span className="badge">прямая</span>
                    )}
                  </td>
                  <td className="small dim">
                    {p.required_by ? (
                      <>
                        ← {p.required_by}
                        {p.required_range ? <code className="dep-range">{p.required_range}</code> : null}
                      </>
                    ) : null}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </>
      ) : null}

      {groups.already_in_base.length ? (
        <>
          <h3>Уже в базе — заявка не создавалась</h3>
          {groups.already_in_base.map((p) => (
            <div key={p.raw} style={{ marginBottom: 8 }}>
              <div className="row">
                <span className="mono">
                  {p.name} {p.version}
                </span>
                {p.status ? <Badge value={p.status} /> : null}
                {p.package_version_id ? (
                  <Link to={`/packages?q=${encodeURIComponent(p.name ?? '')}`}>карточка пакета</Link>
                ) : null}
              </div>
              {p.message ? <div className="small dim">{p.message}</div> : null}
              {p.install_command ? <Copyable command={p.install_command} /> : null}
            </div>
          ))}
        </>
      ) : null}

      {groups.invalid_format.length ? (
        <>
          <h3>Ошибка формата записи</h3>
          <table>
            <tbody>
              {groups.invalid_format.map((p) => (
                <tr key={p.raw}>
                  <td className="mono">{p.raw}</td>
                  <td className="small">
                    {p.message}
                    {p.expected_format ? (
                      <>
                        {' '}
                        Ожидается: <code>{p.expected_format}</code>
                      </>
                    ) : null}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </>
      ) : null}

      {!result.accepted && !groups.already_in_base.length ? (
        <Empty text="Ни один пакет не принят к проверке" />
      ) : null}
    </div>
  )
}
