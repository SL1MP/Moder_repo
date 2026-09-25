import { useCallback, useEffect, useState, type ReactNode } from 'react'

import { fetchFile } from '../lib/api'
import type { DependencyTree, ParsedPackage, Step, Vulnerability } from '../lib/api'

export function Badge({ value, title, label }: { value: string; title?: string; label?: string }) {
  return (
    <span className={`badge ${value}`} title={title}>
      {label ?? STATUS_LABELS[value] ?? title ?? value}
    </span>
  )
}

export const STATUS_LABELS: Record<string, string> = {
  new: 'Новый',
  queued: 'В очереди',
  running: 'Проверяется',
  checking: 'Проверяется',
  pending: 'Проверяется',
  quarantined: 'Карантин',
  awaiting_legal: 'Ждёт юристов',
  license_claimed: 'Лицензия заявлена',
  awaiting_security: 'Ждёт DevSecOps',
  approved: 'Одобрен',
  partially_approved: 'Одобрен частично',
  rejected: 'Отклонён',
  // cancelled — автор закрыл заявку: пакеты больше не нужны. Отдельно от
  // «Отклонён»: то решение роли («нельзя»), а это отказ автора.
  cancelled: 'Закрыто автором',
  revoked: 'Отозван',
  blacklisted: 'Blacklist',
  failed: 'Ошибка',
  pass: 'пройден',
  warn: 'остановка',
  fail: 'провален',
  skipped: 'не выполнялся',
}

export function Alert({ kind, children }: { kind: 'error' | 'warn' | 'info' | 'ok'; children: ReactNode }) {
  return <div className={`alert ${kind}`}>{children}</div>
}

export function Loader({ text = 'Загрузка…' }: { text?: string }) {
  return <div className="loader">{text}</div>
}

export function Empty({ text }: { text: string }) {
  return <div className="empty">{text}</div>
}

export function Copyable({ command }: { command: string }) {
  const [copied, setCopied] = useState(false)
  return (
    <div className="command">
      <code>{command}</code>
      <span className="spacer" />
      <button
        className="small ghost nowrap"
        onClick={() => {
          navigator.clipboard?.writeText(command)
          setCopied(true)
          setTimeout(() => setCopied(false), 1500)
        }}
      >
        {copied ? 'скопировано' : 'копировать'}
      </button>
    </div>
  )
}

export function scoreClass(score: number): string {
  if (score >= 70) return 'high'
  if (score >= 40) return 'mid'
  return 'low'
}

export function Vulns({ items }: { items: Vulnerability[] }) {
  if (!items.length) return null
  return (
    <div className="cve-list">
      {items.map((v) => (
        <div className="cve" key={v.id}>
          <span className={`score ${scoreClass(v.score)}`}>{v.score.toFixed(1)}</span>
          <span className="mono">
            {v.url ? (
              <a href={v.url} target="_blank" rel="noreferrer">
                {v.id}
              </a>
            ) : (
              v.id
            )}
          </span>
          <span className="dim small">
            {v.summary ?? '—'}
            {v.cvss_vector ? <span className="muted"> · {v.cvss_vector}</span> : null}
            {v.fixed_versions?.length ? (
              <span className="muted"> · исправлено в {v.fixed_versions.join(', ')}</span>
            ) : (
              <span className="muted"> · исправленных версий нет</span>
            )}
          </span>
        </div>
      ))}
    </div>
  )
}

// Результат шага и статус заявки — разные шкалы, но слово `pending` есть в
// обеих, а таблица подписей была одна. У заявки `pending` значит «идёт
// модерация», у шага — «шаг ещё не выполнялся», и общая подпись врала: пакет
// стоял в очереди, никто его не обрабатывал, а все девять шагов показывали
// «Проверяется». Снаружи это выглядело как идущая проверка, из-за которой и
// возник вопрос «почему проверка застряла» — она не начиналась.
const STEP_RESULT_LABELS: Record<string, string> = {
  pending: 'не начат',
  running: 'выполняется',
  // info — шаг выполнен, публикацию не блокирует, но по нему есть что сказать:
  // так отдаёт результат SAST. «Пройден» здесь читалось бы как «чисто», хотя
  // находки есть и лежат в отчёте.
  info: 'информация',
}

export function Pipeline({
  steps,
  onRestart,
  restartingStep,
}: {
  steps: Step[]
  onRestart?: (step: Step) => void
  restartingStep?: string | null
}) {
  return (
    <div className="pipeline">
      {steps.map((step) => (
        <div className={`step ${step.result}`} key={step.code}>
          <div className="idx">{step.order}</div>
          <div>
            <div className="title">{step.title}</div>
            {step.message ? <div className="msg">{step.message}</div> : null}
            {step.details ? <StepDetails details={step.details} message={step.message} /> : null}
          </div>
          <div className="right nowrap">
            <Badge value={step.result} label={STEP_RESULT_LABELS[step.result]} />
            {step.finished_at ? (
              <div className="muted small">{formatTime(step.finished_at)}</div>
            ) : null}
            {onRestart && step.result !== 'pending' && step.result !== 'running' ? (
              <button
                className="ghost small"
                disabled={restartingStep !== null && restartingStep !== undefined}
                title="Повторить этот шаг и все следующие"
                onClick={() => onRestart(step)}
              >
                {restartingStep === step.code ? 'запускаю…' : 'повторить отсюда'}
              </button>
            ) : null}
          </div>
        </div>
      ))}
    </div>
  )
}

/**
 * Просмотр файла отчёта: HTML — в песочнице, JSON — текстом.
 *
 * Отчёт лежит за токеном, поэтому открыть его ссылкой нельзя: браузер по
 * обычному <a href> заголовок Authorization не отправляет, и маршрут отвечал
 * 401. Файл загружается запросом с токеном и показывается здесь же.
 *
 * HTML показывается в iframe с sandbox="" — без скриптов и с отдельным
 * origin. Отчёт наш и содержимое пакета в нём экранировано (html/template),
 * но это отчёт о ПОДОЗРИТЕЛЬНОМ пакете: в нём лежат совпавшие фрагменты кода
 * и имена файлов из недоверенного источника. Показывать такое в своём origin,
 * где в sessionStorage лежит токен, незачем — тем более что скрипты отчёту не
 * нужны, он самодостаточен по стилям.
 */
export function ReportViewer({
  title,
  url,
  kind,
  onClose,
}: {
  title: string
  url: string
  kind: 'html' | 'json'
  onClose: () => void
}) {
  const [body, setBody] = useState<string | null>(null)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    let alive = true
    setBody(null)
    setError(null)
    fetchFile(url)
      .then((file) => {
        if (alive) setBody(file.body)
      })
      .catch((e: Error) => {
        if (alive) setError(e.message)
      })
    return () => {
      alive = false
    }
  }, [url])

  // Esc закрывает: модальное окно без выхода с клавиатуры — ловушка.
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') onClose()
    }
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [onClose])

  return (
    <div className="modal-backdrop" onClick={onClose}>
      <div className="modal" onClick={(e) => e.stopPropagation()}>
        <div className="modal-head">
          <strong>{title}</strong>
          <div className="row">
            {body !== null ? (
              // Скачивание из памяти, а не ссылкой на маршрут: ссылка снова
              // ушла бы без токена.
              <a
                className="small"
                download={url.split('/').pop()}
                href={URL.createObjectURL(
                  new Blob([body], {
                    type: kind === 'html' ? 'text/html' : 'application/json',
                  }),
                )}
              >
                скачать
              </a>
            ) : null}
            <button className="ghost small" onClick={onClose}>
              закрыть
            </button>
          </div>
        </div>
        {error ? <Alert kind="error">{error}</Alert> : null}
        {body === null && !error ? <Loader /> : null}
        {body !== null && kind === 'html' ? (
          <iframe className="report-frame" title={title} sandbox="" srcDoc={body} />
        ) : null}
        {body !== null && kind === 'json' ? (
          <pre className="report-json">{prettyJSON(body)}</pre>
        ) : null}
      </div>
    </div>
  )
}

// prettyJSON форматирует отчёт для чтения. Неразобранный текст отдаётся как
// есть: показать сырой ответ полезнее, чем «ошибка разбора» вместо содержимого.
function prettyJSON(body: string): string {
  try {
    return JSON.stringify(JSON.parse(body), null, 2)
  } catch {
    return body
  }
}

const DETAIL_LABELS: Record<string, string> = {
  install_command: 'команда установки',
  s3_key: 'ключ в MinIO',
  sha256: 'sha256',
  size_bytes: 'размер, байт',
  nexus_url: 'URL в артефактори',
  repo: 'репозиторий',
  index_version: 'снапшот OSV',
  scanner: 'сканер',
  max_score: 'максимальный балл',
  threshold: 'порог',
  quarantine_until: 'карантин до',
  days_left: 'осталось дней',
  published_at: 'опубликовано',
  spdx: 'SPDX',
  license_raw: 'лицензия в метаданных',
  reason: 'причина',
  findings_count: 'найдено уязвимостей',
  // Два числа у сканеров содержимого: сколько нашли всего и сколько из этого
  // выше порога. Одного не хватало — «найдено 4, выше порога 0» самый частый
  // случай, и по одному числу он читался неверно.
  findings_total: 'находок сканера',
  findings_blocking: 'из них выше порога',
  advisory: 'информационный шаг',
  scanner_unavailable: 'сканер не отработал',
  state: 'состояние прогона',
  rules: 'сработавшие правила',
  detail: 'подробности прогона',
  notes: 'замечания распаковки',
  decided_by: 'решение принял',
  count: 'срабатываний выше порога',
  age_days: 'возраст снапшота, дней',
  confirmed_for_other_version: 'подтверждена для версии',
  already_in_base: 'уже в базе',
}

function StepDetails({ details, message }: { details: Record<string, unknown>; message?: string | null }) {
  // report_json/report_html — ключи в объектном хранилище. Отчёты показаны
  // отдельным блоком со ссылками, а сырой ключ в деталях шага — шум.
  const hidden = ['findings', 'rule', 'report_json', 'report_html']
  const rows = Object.entries(details).filter(
    ([key, value]) =>
      value !== null &&
      value !== undefined &&
      !hidden.includes(key) &&
      // Деталь, которая целиком уже есть в сообщении шага, — повтор. Живой
      // пример: упавший semgrep кладёт свой stderr и в сообщение, и в
      // `detail`, и карточка показывала одну и ту же простыню дважды.
      !(typeof value === 'string' && message && message.includes(value)),
  )
  const rule = details.rule as Record<string, unknown> | undefined
  if (!rows.length && !rule) return null
  return (
    <div className="details">
      {rule ? (
        <div>
          правило blacklist: {String(rule.name)} ({String(rule.versions)})
          {rule.added_by ? ` · добавил ${String(rule.added_by)}` : ''}
          {rule.added_at ? ` · ${String(rule.added_at)}` : ''}
        </div>
      ) : null}
      {rows.map(([key, value]) => (
        <div key={key}>
          {DETAIL_LABELS[key] ?? key}: {formatDetail(value)}
        </div>
      ))}
    </div>
  )
}

function formatDetail(value: unknown): string {
  if (typeof value === 'boolean') return value ? 'да' : 'нет'
  if (Array.isArray(value)) return value.map((v) => formatDetail(v)).join(', ')
  if (typeof value === 'object' && value) return JSON.stringify(value)
  return String(value)
}

export function formatTime(iso: string | null): string {
  if (!iso) return '—'
  const dt = new Date(iso)
  return dt.toLocaleString('ru-RU', {
    day: '2-digit',
    month: '2-digit',
    year: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
  })
}

export function formatDate(iso: string | null): string {
  if (!iso) return '—'
  return new Date(iso).toLocaleDateString('ru-RU', { day: '2-digit', month: '2-digit', year: 'numeric' })
}

export function waitingLabel(hours: number | null): string {
  if (hours === null) return '—'
  if (hours < 1) return `${Math.round(hours * 60)} мин`
  if (hours < 48) return `${hours.toFixed(1)} ч`
  return `${Math.round(hours / 24)} дн`
}

/** Простая разметка markdown-подобного текста: упоминания и `код`. */
export function renderBody(body: string): ReactNode[] {
  return body.split(/(@[A-Za-z0-9._-]{2,64}|`[^`]+`)/g).map((chunk, i) => {
    if (chunk.startsWith('@')) {
      return (
        <span className="mention" key={i}>
          {chunk}
        </span>
      )
    }
    if (chunk.startsWith('`') && chunk.endsWith('`') && chunk.length > 2) {
      return <code key={i}>{chunk.slice(1, -1)}</code>
    }
    return <span key={i}>{chunk}</span>
  })
}

/** Хук загрузки данных с отображением ошибки в едином формате. */
export function useAsync<T>(loader: () => Promise<T>, deps: unknown[]): {
  data: T | null
  error: string | null
  loading: boolean
  reload: () => void
} {
  const [data, setData] = useState<T | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [loading, setLoading] = useState(true)
  const [tick, setTick] = useState(0)

  useEffect(() => {
    let alive = true
    setLoading(true)
    setError(null)
    loader()
      .then((result) => {
        if (alive) setData(result)
      })
      .catch((exc: Error) => {
        if (alive) setError(exc.message)
      })
      .finally(() => {
        if (alive) setLoading(false)
      })
    return () => {
      alive = false
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [...deps, tick])

  // Стабильная ссылка нужна автообновлению карточки: иначе useEffect видел
  // новую функцию после каждого ответа и пересоздавал таймер без причины.
  const reload = useCallback(() => setTick((t) => t + 1), [])
  return { data, error, loading, reload }
}

/**
 * Дерево зависимостей: что пакет притащит за собой.
 *
 * Показывается отступом по уровню, а не таблицей: происхождение пакета —
 * это связь, и плоский список её теряет. Рядом с каждой строкой — кто
 * потребовал и по какому требованию выбрана версия: без этого «почему в моей
 * заявке urllib3 2.8.0» остаётся без ответа.
 *
 * Три вещи показываются отдельно и заметно, потому что они про то, чего в
 * дереве НЕТ: нераскрытые зависимости, конфликты версий и обрезка по
 * пределу. Неполное дерево выглядит точно так же, как полное.
 */
export function DependencyTreeView({ tree }: { tree: DependencyTree }) {
  const [collapsed, setCollapsed] = useState(false)

  if (!tree.resolved) {
    return (
      <Alert kind="info">
        Менеджер «{tree.manager}» пока не умеет раскрывать зависимости — заведены только
        перечисленные пакеты.
      </Alert>
    )
  }

  return (
    <div className="card">
      <div className="row" style={{ justifyContent: 'space-between', alignItems: 'baseline' }}>
        <h2 style={{ margin: 0 }}>Дерево зависимостей</h2>
        <button className="ghost" onClick={() => setCollapsed((v) => !v)}>
          {collapsed ? 'Показать' : 'Свернуть'}
        </button>
      </div>
      <p className="small dim">
        Заявленных: <b>{tree.direct}</b> · транзитивных: <b>{tree.transitive}</b> · глубина:{' '}
        <b>{tree.depth ?? 0}</b> из {tree.limits.max_depth} · предел заявки:{' '}
        {tree.limits.max_packages} пакетов
        {tree.registry_requests ? ` · запросов в реестр: ${tree.registry_requests}` : ''}
      </p>

      {tree.truncated ? (
        <Alert kind="warn">
          Дерево обрезано по пределу ({tree.limits.max_packages} пакетов): показана часть.
          Уменьшите глубину или заведите оставшееся отдельной заявкой.
        </Alert>
      ) : null}

      {(tree.conflicts ?? []).map((conflict) => (
        <Alert kind="warn" key={conflict.name}>
          <b>{conflict.name}</b> затребован в разных версиях: {conflict.versions.join(', ')}. В
          заявку попадут обе — выбор за вами.
        </Alert>
      ))}

      {(tree.problems ?? []).length ? (
        <Alert kind="warn">
          Не удалось раскрыть {tree.problems?.length} зависимост
          {(tree.problems?.length ?? 0) === 1 ? 'ь' : 'ей'} — в заявку они не попадут:
          <ul className="tree-problems">
            {(tree.problems ?? []).map((problem) => (
              <li key={`${problem.required_by}-${problem.name}`}>
                <code>{problem.name}</code> {problem.constraint}
                {problem.required_by ? <span className="dim"> ← {problem.required_by}</span> : null}
                <div className="small dim">{problem.reason}</div>
              </li>
            ))}
          </ul>
        </Alert>
      ) : null}

      {collapsed ? null : (
        <ul className="dep-tree">
          {tree.packages.map((pkg, index) => (
            <DependencyRow key={`${pkg.raw}-${index}`} pkg={pkg} />
          ))}
        </ul>
      )}
    </div>
  )
}

function DependencyRow({ pkg }: { pkg: ParsedPackage }) {
  const depth = pkg.depth ?? 0
  return (
    <li className="dep-row" style={{ paddingLeft: depth * 18 }}>
      <span className="dep-marker">{depth ? '└' : ''}</span>
      <span className="mono">
        {pkg.name} {pkg.version}
      </span>
      {depth === 0 ? <Badge value="new" label="заявлен" /> : null}
      {pkg.state === 'already_in_base' ? <Badge value="approved" label="уже в базе" /> : null}
      {pkg.state === 'invalid_format' ? <Badge value="fail" label="не разобрано" /> : null}
      {depth > 0 && pkg.required_by ? (
        <span className="small dim">
          ← {pkg.required_by}
          {pkg.required_range ? <code className="dep-range">{pkg.required_range}</code> : null}
        </span>
      ) : null}
    </li>
  )
}
