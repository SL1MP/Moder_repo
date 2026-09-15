import { useState } from 'react'
import { Link } from 'react-router-dom'

import { Alert, Badge, Empty, Loader, formatTime, scoreClass, useAsync, waitingLabel } from '../components/ui'
import { api } from '../lib/api'

export default function QueueSecurity({ onChange }: { onChange: () => void }) {
  const { data, error, loading, reload } = useAsync(() => api.queueSecurity(), [])
  const [busy, setBusy] = useState<number | null>(null)
  const [comment, setComment] = useState<Record<number, string>>({})
  const [failure, setFailure] = useState<string | null>(null)

  const act = (id: number, fn: () => Promise<unknown>) => {
    setBusy(id)
    setFailure(null)
    fn()
      .then(() => {
        reload()
        onChange()
      })
      .catch((exc: Error) => setFailure(exc.message))
      .finally(() => setBusy(null))
  }

  return (
    <>
      <div className="topbar">
        <div>
          <h1>Очередь DevSecOps</h1>
          <p className="page-hint">
            Только то, что ждёт решения DevSecOps: уязвимости выше порога, устаревшая база OSV,
            карантин. Сортировка по времени ожидания.
          </p>
        </div>
        <button className="ghost small" onClick={reload}>
          обновить
        </button>
      </div>

      {error ? <Alert kind="error">{error}</Alert> : null}
      {failure ? <Alert kind="error">{failure}</Alert> : null}
      {loading ? <Loader /> : null}
      {data && !data.length ? <Empty text="Очередь пуста" /> : null}

      {(data ?? []).map((row) => (
        <div className="card" key={row.item_id}>
          <div className="row between">
            <div className="row">
              <b className="mono">
                {row.name} {row.version}
              </b>
              <span className="badge mono">{row.manager}</span>
              <Badge value={row.status} title={row.status_title} />
              {row.max_vuln_score ? (
                <span className={`score ${scoreClass(row.max_vuln_score)}`}>
                  {row.max_vuln_score.toFixed(1)}
                </span>
              ) : null}
            </div>
            <div className="small muted nowrap">
              ждёт {waitingLabel(row.waiting_hours)} · с {formatTime(row.waiting_since)} · автор{' '}
              {row.author ?? '—'} ·{' '}
              <Link to={`/requests/${row.request_id}`}>заявка #{row.request_id}</Link>
            </div>
          </div>

          {row.blocked_reason ? (
            <div className="small dim" style={{ marginTop: 6 }}>
              {row.blocked_reason}
            </div>
          ) : null}

          <div className="row" style={{ marginTop: 8 }}>
            <input
              className="wide"
              placeholder="Комментарий (обязателен при отклонении)"
              value={comment[row.item_id] ?? ''}
              onChange={(e) => setComment({ ...comment, [row.item_id]: e.target.value })}
            />
            {row.status === 'quarantined' ? (
              <button
                className="primary small nowrap"
                disabled={busy === row.item_id}
                onClick={() =>
                  act(row.item_id, () =>
                    api.releaseQuarantine(row.item_id, comment[row.item_id] ?? ''),
                  )
                }
              >
                снять карантин
              </button>
            ) : (
              <>
                <button
                  className="primary small nowrap"
                  disabled={busy === row.item_id}
                  onClick={() =>
                    act(row.item_id, () =>
                      api.securityDecision(row.item_id, true, comment[row.item_id] ?? ''),
                    )
                  }
                >
                  разрешить
                </button>
                <button
                  className="danger small nowrap"
                  disabled={busy === row.item_id || !(comment[row.item_id] ?? '').trim()}
                  onClick={() =>
                    act(row.item_id, () =>
                      api.securityDecision(row.item_id, false, comment[row.item_id] ?? ''),
                    )
                  }
                >
                  отклонить
                </button>
              </>
            )}
          </div>
        </div>
      ))}
    </>
  )
}
