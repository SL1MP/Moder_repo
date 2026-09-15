import { useState } from 'react'
import { Link } from 'react-router-dom'

import { Alert, Badge, Empty, Loader, formatTime, useAsync, waitingLabel } from '../components/ui'
import { api, type LicenseClaim } from '../lib/api'

export default function QueueLegal({ onChange }: { onChange: () => void }) {
  const queue = useAsync(() => api.queueLegal(), [])
  const claims = useAsync(() => api.licenseClaims('pending'), [])
  const [failure, setFailure] = useState<string | null>(null)

  const reload = () => {
    queue.reload()
    claims.reload()
    onChange()
  }

  return (
    <>
      <div className="topbar">
        <div>
          <h1>Очередь юристов</h1>
          <p className="page-hint">
            Пакеты, остановленные на шаге «Лицензия»: SPDX не определился или отсутствует в
            справочнике разрешённых. Сортировка по времени ожидания.
          </p>
        </div>
        <button className="ghost small" onClick={reload}>
          обновить
        </button>
      </div>

      {queue.error ? <Alert kind="error">{queue.error}</Alert> : null}
      {failure ? <Alert kind="error">{failure}</Alert> : null}
      {queue.loading ? <Loader /> : null}
      {queue.data && !queue.data.length ? <Empty text="Очередь пуста" /> : null}

      {(queue.data ?? []).map((row) => {
        const claim = claims.data?.find((c) => c.request_item_id === row.item_id)
        return (
          <div className="card" key={row.item_id}>
            <div className="row between">
              <div className="row">
                <b className="mono">
                  {row.name} {row.version}
                </b>
                <span className="badge mono">{row.manager}</span>
                <Badge value={row.status} title={row.status_title} />
                {row.license_spdx ? <span className="badge mono">{row.license_spdx}</span> : null}
              </div>
              <div className="small muted nowrap">
                ждёт {waitingLabel(row.waiting_hours)} · автор {row.author ?? '—'} ·{' '}
                <Link to={`/requests/${row.request_id}`}>заявка #{row.request_id}</Link>
              </div>
            </div>
            {row.blocked_reason ? (
              <div className="small dim" style={{ marginTop: 6 }}>
                {row.blocked_reason}
              </div>
            ) : null}

            {claim ? (
              <ClaimDecision claim={claim} onDone={reload} onError={setFailure} />
            ) : (
              <Alert kind="info">
                Лицензия ещё не заявлена разработчиком. Ждём ссылку на файл лицензии или страницу
                проекта.
              </Alert>
            )}
          </div>
        )
      })}
    </>
  )
}

function ClaimDecision({
  claim,
  onDone,
  onError,
}: {
  claim: LicenseClaim
  onDone: () => void
  onError: (message: string) => void
}) {
  const [comment, setComment] = useState('')
  const [busy, setBusy] = useState(false)
  const [showSnapshot, setShowSnapshot] = useState(false)

  const decide = (approve: boolean) => {
    setBusy(true)
    api
      .decideLicense(claim.id, approve, comment)
      .then(onDone)
      .catch((exc: Error) => onError(exc.message))
      .finally(() => setBusy(false))
  }

  return (
    <div style={{ marginTop: 8 }}>
      <dl className="kv">
        <dt>Заявленная ссылка</dt>
        <dd>
          <a href={claim.url} target="_blank" rel="noreferrer">
            {claim.url}
          </a>
        </dd>
        <dt>SPDX</dt>
        <dd className="mono">{claim.spdx_id ?? 'не указан'}</dd>
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
          <button className="ghost small" onClick={() => setShowSnapshot(!showSnapshot)}>
            {showSnapshot ? 'скрыть снапшот текста' : 'показать снапшот текста по ссылке'}
          </button>
          {showSnapshot ? <pre className="snapshot">{claim.snapshot_text}</pre> : null}
        </>
      ) : null}

      <textarea
        placeholder="Комментарий (обязателен при отклонении)"
        value={comment}
        onChange={(e) => setComment(e.target.value)}
      />
      <div className="row">
        <button className="primary small" disabled={busy} onClick={() => decide(true)}>
          подтвердить
        </button>
        <button
          className="danger small"
          disabled={busy || !comment.trim()}
          onClick={() => decide(false)}
        >
          отклонить
        </button>
      </div>
    </div>
  )
}
