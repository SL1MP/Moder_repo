import { useEffect, useState, type ReactNode } from 'react'

import type { Step, Vulnerability } from '../lib/api'

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
  // info — шаг выполнен, публикацию не блокирует, но по нему есть что сказать:
  // так отдаёт результат SAST. «Пройден» здесь читалось бы как «чисто», хотя
  // находки есть и лежат в отчёте.
  info: 'информация',
}

export function Pipeline({ steps }: { steps: Step[] }) {
  return (
    <div className="pipeline">
      {steps.map((step) => (
        <div className={`step ${step.result}`} key={step.code}>
          <div className="idx">{step.order}</div>
          <div>
            <div className="title">{step.title}</div>
            {step.message ? <div className="msg">{step.message}</div> : null}
            {step.details ? <StepDetails details={step.details} /> : null}
          </div>
          <div className="right nowrap">
            <Badge value={step.result} label={STEP_RESULT_LABELS[step.result]} />
            {step.finished_at ? (
              <div className="muted small">{formatTime(step.finished_at)}</div>
            ) : null}
          </div>
        </div>
      ))}
    </div>
  )
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

function StepDetails({ details }: { details: Record<string, unknown> }) {
  // report_json/report_html — ключи в объектном хранилище. Отчёты показаны
  // отдельным блоком со ссылками, а сырой ключ в деталях шага — шум.
  const hidden = ['findings', 'rule', 'report_json', 'report_html']
  const rows = Object.entries(details).filter(
    ([key, value]) => value !== null && value !== undefined && !hidden.includes(key),
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

  return { data, error, loading, reload: () => setTick((t) => t + 1) }
}
