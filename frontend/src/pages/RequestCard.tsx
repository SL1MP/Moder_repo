import { useEffect, useState } from 'react'
import { useParams } from 'react-router-dom'

import {
  Alert,
  Badge,
  Copyable,
  Empty,
  Loader,
  Pipeline,
  Vulns,
  formatDate,
  formatTime,
  renderBody,
  useAsync,
} from '../components/ui'
import {
  api,
  type CodeFinding as CodeFindingRow,
  type Comment,
  type LicenseClaim,
  type Me,
  type RequestItem,
} from '../lib/api'

export default function RequestCard({ me, onChange }: { me: Me; onChange: () => void }) {
  const { id } = useParams()
  const requestId = Number(id)
  const { data, error, loading, reload } = useAsync(() => api.requestById(requestId), [requestId])
  const [expanded, setExpanded] = useState<number | null>(null)
  const [closing, setClosing] = useState(false)
  const [closeError, setCloseError] = useState<string | null>(null)

  // Пока заявка в работе — обновляем состояние: конвейер выполняется асинхронно.
  useEffect(() => {
    if (!data || !['pending'].includes(data.status)) return
    const timer = setTimeout(reload, 4000)
    return () => clearTimeout(timer)
  }, [data, reload])

  if (loading && !data) return <Loader />
  if (error) return <Alert kind="error">{error}</Alert>
  if (!data) return <Empty text="Заявка не найдена" />

  const s = data.summary
  return (
    <>
      <div className="topbar">
        <div>
          <h1>
            Заявка #{data.request_id} <Badge value={data.status} title={data.status_title} />
          </h1>
          <p className="page-hint">
            {data.status_title} · менеджер <code>{data.manager}</code> · автор {data.author ?? '—'}
            {data.author_role ? ` (${data.author_role})` : ''} · создана {formatTime(data.created_at)}
            {data.origin_file ? (
              <>
                {' '}
                · источник <code>{data.origin_file}</code>
              </>
            ) : null}
          </p>
        </div>
        <div className="row">
          {data.summary.failed ? (
            <button
              className="small"
              onClick={() => api.retryRequest(requestId).then(reload).catch(() => reload())}
            >
              перезапустить проверку
            </button>
          ) : null}
          {data.can_cancel ? (
            <button
              className="danger small"
              disabled={closing}
              // Подтверждение обязательно: кнопка стоит рядом с «обновить», а
              // отменённые пакеты назад не вернуть — только новой заявкой.
              onClick={() => {
                const left = data.summary.cancellable
                if (!window.confirm(
                  `Закрыть заявку #${requestId}? Проверка ${left} ` +
                    'незавершённых пакетов будет прекращена. Вернуть их можно только новой заявкой.',
                )) {
                  return
                }
                setClosing(true)
                setCloseError(null)
                api
                  .cancelRequest(requestId)
                  .then(() => {
                    reload()
                    // Счётчики очередей ролей меняются: заявка из них ушла.
                    onChange()
                  })
                  .catch((e: Error) => setCloseError(e.message))
                  .finally(() => setClosing(false))
              }}
            >
              {closing ? 'закрываю…' : 'закрыть заявку'}
            </button>
          ) : null}
          <button className="ghost small" onClick={reload}>
            обновить
          </button>
        </div>
      </div>

      {closeError ? <Alert kind="error">{closeError}</Alert> : null}

      <div className="card tight">
        <div className="row">
          <Summary label="Всего пакетов" value={s.total} />
          <Summary label="Одобрено автоматически" value={s.approved} ok />
          <Summary label="Ждут DevSecOps" value={s.awaiting_security} warn />
          <Summary label="Ждут юристов" value={s.awaiting_legal} warn />
          <Summary label="В карантине" value={s.quarantined} warn />
          <Summary label="Отклонено" value={s.rejected} bad />
          {s.cancelled ? <Summary label="Закрыто автором" value={s.cancelled} /> : null}
          {s.failed ? <Summary label="Ошибка проверки" value={s.failed} bad /> : null}
        </div>
        {data.reason ? <div className="small dim">Обоснование: {data.reason}</div> : null}
      </div>

      {data.warnings.map((w, i) => (
        <Alert kind="warn" key={i}>
          {w}
        </Alert>
      ))}

      {data.packages.map((item) => (
        <PackageBlock
          key={item.id}
          item={item}
          me={me}
          requestId={requestId}
          expanded={expanded === item.id}
          onToggle={() => setExpanded(expanded === item.id ? null : item.id)}
          onChanged={() => {
            reload()
            onChange()
          }}
        />
      ))}

      <Discussion requestId={requestId} title="Обсуждение заявки" itemId={null} />
    </>
  )
}

function Summary({
  label,
  value,
  ok,
  warn,
  bad,
}: {
  label: string
  value: number
  ok?: boolean
  warn?: boolean
  bad?: boolean
}) {
  const color = ok ? 'var(--pass)' : warn ? 'var(--warn)' : bad ? 'var(--fail)' : 'var(--text)'
  return (
    <div style={{ minWidth: 130 }}>
      <div className="small muted">{label}</div>
      <div style={{ fontSize: 18, fontWeight: 600, color: value ? color : 'var(--text-faint)' }}>
        {value}
      </div>
    </div>
  )
}

function PackageBlock({
  item,
  me,
  requestId,
  expanded,
  onToggle,
  onChanged,
}: {
  item: RequestItem
  me: Me
  requestId: number
  expanded: boolean
  onToggle: () => void
  onChanged: () => void
}) {
  const isSec = me.roles.includes('devsecops') || me.roles.includes('admin')
  const isLegal = me.roles.includes('legal') || me.roles.includes('admin')

  return (
    <div className="card">
      <div className="row between">
        <div className="row">
          <button className="ghost small nowrap" onClick={onToggle}>
            {expanded ? '▾' : '▸'}
          </button>
          <b className="mono">
            {item.name} {item.version}
          </b>
          <Badge value={item.status} title={item.status_title} />
          {item.dependency_kind === 'transitive' ? (
            <span className="badge">транзитивная</span>
          ) : null}
          {item.license_spdx ? <span className="badge mono">{item.license_spdx}</span> : null}
          {item.max_vuln_score ? (
            <span className="badge">макс. балл {item.max_vuln_score.toFixed(1)}</span>
          ) : null}
        </div>
        <div className="small muted nowrap">
          {item.current_step_title ? `шаг: ${item.current_step_title}` : null}
          {item.quarantine_until ? ` · карантин до ${formatDate(item.quarantine_until)}` : null}
        </div>
      </div>

      {item.blocked_reason ? (
        <div className="small dim" style={{ marginTop: 6 }}>
          {item.blocked_reason}
        </div>
      ) : null}

      {item.next_action ? (
        <div className="next-action" style={{ marginTop: 8 }}>
          <strong>Что делать:</strong> {item.next_action}
        </div>
      ) : null}

      {item.install_command ? (
        <div style={{ marginTop: 8 }}>
          <Copyable command={item.install_command} />
        </div>
      ) : null}

      {expanded ? (
        <>
          <h3 style={{ marginTop: 12 }}>Конвейер проверок</h3>
          <Pipeline steps={item.steps} />

          {item.vulnerabilities.length ? (
            <>
              <h3 style={{ marginTop: 12 }}>Найденные уязвимости</h3>
              <Vulns items={item.vulnerabilities} />
            </>
          ) : null}

          {(item.code_findings ?? []).length ? (
            <>
              <h3 style={{ marginTop: 12 }}>Находки сканеров содержимого</h3>
              <CodeFindings items={item.code_findings} />
            </>
          ) : null}

          <ScanReports itemId={item.id} />

          <Actions item={item} isSec={isSec} isLegal={isLegal} onChanged={onChanged} />
          <Discussion requestId={requestId} itemId={item.id} title="Обсуждение пакета" />
        </>
      ) : null}
    </div>
  )
}

/**
 * Отчёты о прогонах сканеров содержимого.
 *
 * Отчёты формирует Go-версия backend'а; python-версия их не делает. Поэтому
 * блок устроен мягко: пустой список и недоступность сервиса — нормальные
 * состояния, а не ошибка карточки. Иначе у всех, кто Go-версию не поднимал,
 * в каждой карточке висела бы красная ошибка.
 */
function ScanReports({ itemId }: { itemId: number }) {
  const reports = useAsync(() => api.scanReports(itemId), [itemId])

  // Сервис не поднят или маршрут не проброшен — молча ничего не показываем.
  if (reports.error) return null
  if (reports.loading) return null
  const items = reports.data?.reports ?? []
  if (!items.length) return null

  return (
    <>
      <h3 style={{ marginTop: 12 }}>Отчёты о сканировании</h3>
      <table className="grid">
        <thead>
          <tr>
            <th>Проверка</th>
            <th>Результат</th>
            <th>Находки</th>
            <th>Чем и по каким правилам</th>
            <th>Отчёт</th>
          </tr>
        </thead>
        <tbody>
          {items.map((r) => (
            <tr key={r.step_code}>
              <td>{r.step_title}</td>
              <td className="nowrap">
                <Badge value={r.state_title} title={r.detail ?? undefined} />
              </td>
              <td className="nowrap">
                {r.state === 'unavailable' ? (
                  // Пустой список находок здесь НЕ означает «чисто»: прогон не
                  // состоялся. Показать «0» было бы прямой дезинформацией.
                  <span className="muted">не проверялось</span>
                ) : r.findings_total === 0 ? (
                  <span className="muted">нет</span>
                ) : (
                  <>
                    {r.findings_total}
                    {r.findings_blocking > 0 ? (
                      <span className="small"> · блокирует: {r.findings_blocking}</span>
                    ) : (
                      <span className="small muted"> · ниже порога «{r.threshold}»</span>
                    )}
                  </>
                )}
              </td>
              <td className="small">
                {r.scanner}
                {r.rules ? <span className="muted"> · {r.rules}</span> : null}
              </td>
              <td className="nowrap">
                <a href={r.html_url} target="_blank" rel="noreferrer">
                  смотреть
                </a>
                <span className="muted"> · </span>
                <a href={r.json_url} target="_blank" rel="noreferrer">
                  JSON
                </a>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
      <p className="small muted" style={{ marginTop: 4 }}>
        Отчёт — снимок прогона: по нему видно, чем и по каким правилам
        проверяли, даже если находок нет.
      </p>
    </>
  )
}

/** Политические баннеры и срабатывания SAST — с файлом и строкой. */
function CodeFindings({ items }: { items: CodeFindingRow[] }) {
  const title: Record<string, string> = { yara: 'Баннеры', semgrep: 'SAST' }
  return (
    <div className="table-wrap">
      <table>
        <thead>
          <tr>
            <th>Сканер</th>
            <th>Правило</th>
            <th>Важность</th>
            <th>Файл</th>
            <th>Совпадение</th>
          </tr>
        </thead>
        <tbody>
          {items.map((f, i) => (
            <tr key={`${f.scanner}-${f.rule_id}-${f.file}-${f.line}-${i}`}>
              <td>{title[f.scanner] ?? f.scanner}</td>
              <td className="mono">{f.rule_id}</td>
              <td>
                <span className={`badge ${f.severity}`}>{f.severity}</span>
              </td>
              <td className="mono small">
                {f.file ?? '—'}
                {f.line ? `:${f.line}` : ''}
              </td>
              <td className="small">{f.matched || f.message || '—'}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}

function Actions({
  item,
  isSec,
  isLegal,
  onChanged,
}: {
  item: RequestItem
  isSec: boolean
  isLegal: boolean
  onChanged: () => void
}) {
  // Блоки решений выбираются по списку открытых блокировок, а не по статусу.
  // Статус у пакета один, а ждать он может двух решений сразу: раньше цепочка
  // `if (status === ...)` с ранним возвратом отдавала блок DevSecOps и до блока
  // лицензии не доходила — юрист не мог поставить апрув, пока не решит DevSecOps.
  const pending = item.pending ?? []
  const waitsQuarantine = pending.includes('quarantine') || item.status === 'quarantined'
  const waitsSecurity = pending.includes('vuln_scan') || item.status === 'awaiting_security'
  const waitsLegal =
    pending.includes('license') ||
    item.status === 'awaiting_legal' ||
    item.status === 'license_claimed'

  if (!waitsQuarantine && !waitsSecurity && !waitsLegal) return null

  return (
    <>
      {waitsQuarantine ? (
        <QuarantineBlock item={item} isSec={isSec} onChanged={onChanged} />
      ) : null}
      {waitsSecurity ? <SecurityBlock item={item} isSec={isSec} onChanged={onChanged} /> : null}
      {waitsLegal ? <LicenseBlock item={item} isLegal={isLegal} onChanged={onChanged} /> : null}
    </>
  )
}

/** Общее состояние блоков решений: комментарий, блокировка кнопок, ошибка. */
function useDecision(onChanged: () => void) {
  const [comment, setComment] = useState('')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)

  const run = (fn: () => Promise<unknown>) => {
    setBusy(true)
    setError(null)
    fn()
      .then(() => {
        setComment('')
        onChanged()
      })
      .catch((exc: Error) => setError(exc.message))
      .finally(() => setBusy(false))
  }

  return { comment, setComment, busy, error, run }
}

function QuarantineBlock({
  item,
  isSec,
  onChanged,
}: {
  item: RequestItem
  isSec: boolean
  onChanged: () => void
}) {
  const { comment, setComment, busy, error, run } = useDecision(onChanged)

  return (
    <div className="card tight" style={{ marginTop: 12 }}>
      <h3>Карантин</h3>
      <p className="small dim">
        Проверка продолжится автоматически после окончания карантина
        {item.quarantine_until ? ` (${formatDate(item.quarantine_until)})` : ''}. DevSecOps может
        снять карантин досрочно.
      </p>
      {error ? <Alert kind="error">{error}</Alert> : null}
      {isSec ? (
        <div className="row">
          <input
            className="wide"
            placeholder="Комментарий к досрочному снятию"
            value={comment}
            onChange={(e) => setComment(e.target.value)}
          />
          <button
            className="primary small nowrap"
            disabled={busy}
            onClick={() => run(() => api.releaseQuarantine(item.id, comment))}
          >
            снять карантин
          </button>
        </div>
      ) : null}
    </div>
  )
}

function SecurityBlock({
  item,
  isSec,
  onChanged,
}: {
  item: RequestItem
  isSec: boolean
  onChanged: () => void
}) {
  const { comment, setComment, busy, error, run } = useDecision(onChanged)

  return (
    <div className="card tight" style={{ marginTop: 12 }}>
      <h3>Решение DevSecOps</h3>
      {error ? <Alert kind="error">{error}</Alert> : null}
      {isSec ? (
        <>
          <textarea
            placeholder="Комментарий (обязателен при отклонении)"
            value={comment}
            onChange={(e) => setComment(e.target.value)}
          />
          <div className="row">
            <button
              className="primary small"
              disabled={busy}
              onClick={() => run(() => api.securityDecision(item.id, true, comment))}
            >
              разрешить публикацию
            </button>
            <button
              className="danger small"
              disabled={busy || !comment.trim()}
              onClick={() => run(() => api.securityDecision(item.id, false, comment))}
            >
              отклонить
            </button>
          </div>
        </>
      ) : (
        <p className="small dim">Заявка передана DevSecOps, ожидайте решения.</p>
      )}
    </div>
  )
}

function LicenseBlock({
  item,
  isLegal,
  onChanged,
}: {
  item: RequestItem
  isLegal: boolean
  onChanged: () => void
}) {
  const licenses = useAsync(() => api.licenses(), [])
  const claims = useAsync(() => api.licenseClaims('pending'), [item.status])
  const [url, setUrl] = useState('')
  const [spdx, setSpdx] = useState('')
  const [comment, setComment] = useState('')
  const [decision, setDecision] = useState('')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)

  const claim: LicenseClaim | undefined = claims.data?.find((c) => c.request_item_id === item.id)

  return (
    <div className="card tight" style={{ marginTop: 12 }}>
      <h3>Лицензия</h3>
      {error ? <Alert kind="error">{error}</Alert> : null}

      {claim ? (
        <>
          <dl className="kv">
            <dt>Ссылка</dt>
            <dd>
              <a href={claim.url} target="_blank" rel="noreferrer">
                {claim.url}
              </a>
            </dd>
            <dt>SPDX</dt>
            <dd className="mono">{claim.spdx_id ?? '—'}</dd>
            <dt>Заявил</dt>
            <dd>
              {claim.claimed_by ?? '—'} · {formatTime(claim.created_at)}
            </dd>
            {claim.comment ? (
              <>
                <dt>Комментарий</dt>
                <dd>{claim.comment}</dd>
              </>
            ) : null}
          </dl>
          {claim.suggested_license ? <Alert kind="info">{claim.suggested_license.note}</Alert> : null}
          {claim.snapshot_text ? (
            <>
              <h3 style={{ marginTop: 10 }}>Снапшот текста по ссылке</h3>
              <pre className="snapshot">{claim.snapshot_text}</pre>
            </>
          ) : null}
          {isLegal ? (
            <>
              <textarea
                placeholder="Комментарий юриста (обязателен при отклонении)"
                value={decision}
                onChange={(e) => setDecision(e.target.value)}
              />
              <div className="row">
                <button
                  className="primary small"
                  disabled={busy}
                  onClick={() => {
                    setBusy(true)
                    api
                      .decideLicense(claim.id, true, decision)
                      .then(onChanged)
                      .catch((exc: Error) => setError(exc.message))
                      .finally(() => setBusy(false))
                  }}
                >
                  подтвердить лицензию
                </button>
                <button
                  className="danger small"
                  disabled={busy || !decision.trim()}
                  onClick={() => {
                    setBusy(true)
                    api
                      .decideLicense(claim.id, false, decision)
                      .then(onChanged)
                      .catch((exc: Error) => setError(exc.message))
                      .finally(() => setBusy(false))
                  }}
                >
                  отклонить
                </button>
              </div>
            </>
          ) : (
            <p className="small dim">Лицензия заявлена, ожидается подтверждение юриста.</p>
          )}
        </>
      ) : (
        <>
          <p className="small dim">
            Приложите ссылку на файл лицензии или страницу проекта. Ссылка должна открываться без
            авторизации — сервис сохранит снапшот текста для юриста.
          </p>
          <label>
            <span>Ссылка на лицензию</span>
            <input
              className="wide"
              value={url}
              onChange={(e) => setUrl(e.target.value)}
              placeholder="https://github.com/org/repo/blob/main/LICENSE"
            />
          </label>
          <label>
            <span>SPDX-идентификатор (необязательно)</span>
            {/* Только выбор из справочника: произвольный идентификатор юрист
                всё равно не сможет сверить, а опечатка в нём тихо ломает
                автоматическую проверку лицензии на следующем прогоне. */}
            <select className="wide" value={spdx} onChange={(e) => setSpdx(e.target.value)}>
              <option value="">— не указывать —</option>
              {(licenses.data?.allowed ?? []).map((l) => (
                <option key={l.spdx_id} value={l.spdx_id}>
                  {l.spdx_id}
                  {l.name && l.name !== l.spdx_id ? ` — ${l.name}` : ''}
                </option>
              ))}
            </select>
          </label>
          <label>
            <span>Комментарий юристам</span>
            <textarea value={comment} onChange={(e) => setComment(e.target.value)} />
          </label>
          <button
            className="primary small"
            disabled={busy || !url.trim()}
            onClick={() => {
              setBusy(true)
              setError(null)
              api
                .claimLicense(item.id, {
                  url,
                  spdx_id: spdx || undefined,
                  comment: comment || undefined,
                })
                .then(onChanged)
                .catch((exc: Error) => setError(exc.message))
                .finally(() => setBusy(false))
            }}
          >
            заявить лицензию
          </button>
        </>
      )}
    </div>
  )
}

function Discussion({
  requestId,
  itemId,
  title,
}: {
  requestId: number
  itemId: number | null
  title: string
}) {
  const { data, error, reload } = useAsync(
    () => api.comments(requestId, itemId ?? undefined),
    [requestId, itemId],
  )
  const [body, setBody] = useState('')
  const [busy, setBusy] = useState(false)
  const [failure, setFailure] = useState<string | null>(null)

  const own = (data ?? []).filter((c) => (itemId ? c.request_item_id === itemId : !c.request_item_id))

  return (
    <div className="card tight" style={{ marginTop: 12 }}>
      <h3>
        {title} ({own.length})
      </h3>
      {error ? <Alert kind="error">{error}</Alert> : null}
      {failure ? <Alert kind="error">{failure}</Alert> : null}
      {own.map((comment) => (
        <CommentRow key={comment.id} comment={comment} onChanged={reload} />
      ))}
      <textarea
        value={body}
        onChange={(e) => setBody(e.target.value)}
        placeholder="Сообщение. Поддерживаются упоминания @логин и `код`."
      />
      <button
        className="small"
        disabled={busy || !body.trim()}
        onClick={() => {
          setBusy(true)
          setFailure(null)
          api
            .addComment(requestId, body, itemId)
            .then(() => {
              setBody('')
              reload()
            })
            .catch((exc: Error) => setFailure(exc.message))
            .finally(() => setBusy(false))
        }}
      >
        отправить
      </button>
    </div>
  )
}

function CommentRow({ comment, onChanged }: { comment: Comment; onChanged: () => void }) {
  const [editing, setEditing] = useState(false)
  const [draft, setDraft] = useState(comment.body)

  return (
    <div className="comment">
      <div className="comment-head">
        <b>{comment.author}</b>
        {comment.author_role ? <span className="badge">{comment.author_role}</span> : null}
        <span className="muted small">{formatTime(comment.created_at)}</span>
        {comment.is_edited ? <span className="muted small">· изменено</span> : null}
        {comment.deleted ? <span className="muted small">· удалено</span> : null}
        <span className="spacer" />
        {comment.can_edit ? (
          <>
            <button className="ghost small" onClick={() => setEditing(!editing)}>
              {editing ? 'отмена' : 'изменить'}
            </button>
            <button
              className="ghost small"
              onClick={() => api.deleteComment(comment.id).then(onChanged)}
            >
              удалить
            </button>
          </>
        ) : null}
      </div>
      {editing ? (
        <div>
          <textarea value={draft} onChange={(e) => setDraft(e.target.value)} />
          <button
            className="small"
            onClick={() =>
              api.editComment(comment.id, draft).then(() => {
                setEditing(false)
                onChanged()
              })
            }
          >
            сохранить
          </button>
        </div>
      ) : (
        <div className="comment-body">{renderBody(comment.body)}</div>
      )}
    </div>
  )
}
