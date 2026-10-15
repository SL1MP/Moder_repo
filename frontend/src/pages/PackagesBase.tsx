import { useEffect, useState } from 'react'
import { Link, useSearchParams } from 'react-router-dom'

import {
  Alert,
  Badge,
  Copyable,
  Empty,
  Loader,
  Vulns,
  formatDate,
  scoreClass,
  useAsync,
} from '../components/ui'
import { api, type Manager, type Me, type PackageVersion } from '../lib/api'

const STATUSES = [
  { value: '', label: 'все доступные статусы' },
  { value: 'approved', label: 'одобрен' },
  { value: 'quarantined', label: 'карантин' },
  { value: 'awaiting_legal', label: 'ждёт юристов' },
  { value: 'awaiting_security', label: 'ждёт DevSecOps' },
]

const PAGE_SIZE = 50
const VISIBLE_STATUSES = new Set(STATUSES.map((item) => item.value))

export default function PackagesBase({ me }: { me: Me }) {
  const [params, setParams] = useSearchParams()
  const [query, setQuery] = useState(params.get('q') ?? '')
  const [manager, setManager] = useState<Manager | ''>('')
  const [version, setVersion] = useState('')
  const initialStatus = params.get('status') ?? ''
  const [status, setStatus] = useState(VISIBLE_STATUSES.has(initialStatus) ? initialStatus : '')
  const [selected, setSelected] = useState<number | null>(null)
  const [page, setPage] = useState(0)
  // Список менеджеров берём у сервиса, а не перечисляем здесь: их двенадцать,
  // и зашитый список молча отстаёт от бэкенда — ровно так docker не появлялся
  // в поиске после того, как его уже поддержали.
  const managers = useAsync(() => api.managers(), [])
  useEffect(() => { setPage(0); setSelected(null) }, [query, manager, version, status])

  const { data, error, loading, reload } = useAsync(
    () =>
      api.packages({
        ...(query ? { q: query } : {}),
        ...(manager ? { manager } : {}),
        ...(version ? { version } : {}),
        ...(status ? { status } : {}),
        limit: String(PAGE_SIZE),
        offset: String(page * PAGE_SIZE),
      }),
    [query, manager, version, status, page],
  )

  return (
    <>
      <div className="topbar">
        <div>
          <h1>База пакетов</h1>
          <p className="page-hint">
            Поиск по имени, версии, менеджеру и статусу. Для одобренных показана готовая команда
            установки из внутреннего репозитория.
          </p>
        </div>
        <button className="ghost small" onClick={reload}>
          обновить
        </button>
      </div>

      <div className="card tight">
        <form
          className="row"
          onSubmit={(event) => {
            event.preventDefault()
            setParams({ ...(query ? { q: query } : {}), ...(status ? { status } : {}) })
          }}
        >
          <label style={{ margin: 0, minWidth: 240 }}>
            <span>Имя пакета</span>
            <input className="wide" value={query} onChange={(e) => setQuery(e.target.value)} />
          </label>
          <label style={{ margin: 0 }}>
            <span>Менеджер</span>
            <select value={manager} onChange={(e) => setManager(e.target.value as Manager | '')}>
              <option value="">все</option>
              {(managers.data ?? []).map((m) => (
                <option key={m.code} value={m.code}>
                  {m.code}
                </option>
              ))}
            </select>
          </label>
          <label style={{ margin: 0, minWidth: 120 }}>
            <span>Версия</span>
            <input className="wide" value={version} onChange={(e) => setVersion(e.target.value)} />
          </label>
          <label style={{ margin: 0 }}>
            <span>Статус</span>
            <select value={status} onChange={(e) => setStatus(e.target.value)}>
              {STATUSES.map((s) => (
                <option key={s.value} value={s.value}>
                  {s.label}
                </option>
              ))}
            </select>
          </label>
          <button type="submit" className="small" style={{ marginTop: 14 }}>
            найти
          </button>
        </form>
      </div>

      {error ? <Alert kind="error">{error}</Alert> : null}
      {loading ? <Loader /> : null}
      {data && !data.items.length ? <Empty text="Ничего не найдено" /> : null}

      {data && data.items.length ? (
        <div className="card">
          <div className="small muted" style={{ marginBottom: 6 }}>
            Найдено: {data.total}
          </div>
          <div className="table-scroll package-base-table"><table>
            <thead>
              <tr>
                <th>Пакет</th>
                <th>Версия</th>
                <th>Менеджер</th>
                <th>Статус</th>
                <th>Лицензия</th>
                <th>Балл</th>
                <th>Опубликован</th>
                <th>Одобрен</th>
                <th />
              </tr>
            </thead>
            <tbody>
              {data.items.map((pkg) => (
                <PackageRow key={pkg.id} pkg={pkg} selected={selected === pkg.id}
                  onToggle={() => setSelected(selected === pkg.id ? null : pkg.id)}
                  me={me} onChanged={reload} />
              ))}
            </tbody>
          </table></div>
        </div>
      ) : null}

      {data && (page > 0 || (page + 1) * PAGE_SIZE < data.total) ? (
        <div className="card tight row between">
          <button className="ghost small" disabled={loading || page === 0}
            onClick={() => setPage((current) => Math.max(0, current - 1))}>← предыдущая</button>
          <span className="small muted">
            {page * PAGE_SIZE + 1}–{Math.min((page + 1) * PAGE_SIZE, data.total)} из {data.total}
          </span>
          <button className="ghost small" disabled={loading || (page + 1) * PAGE_SIZE >= data.total}
            onClick={() => setPage((current) => current + 1)}>следующая →</button>
        </div>
      ) : null}
    </>
  )
}

function PackageRow({ pkg, selected, onToggle, me, onChanged }: {
  pkg: PackageVersion
  selected: boolean
  onToggle: () => void
  me: Me
  onChanged: () => void
}) {
  return (
    <>
      <tr className={selected ? 'selected-row' : ''}>
                  <td className="mono">{pkg.name}</td>
                  <td className="mono">{pkg.version}</td>
                  <td>
                    <span className="badge mono">{pkg.manager}</span>
                  </td>
                  <td>
                    <Badge value={pkg.status} />
                  </td>
                  <td className="mono small">{pkg.license_spdx ?? '—'}</td>
                  <td className="num">
                    {pkg.max_vuln_score ? (
                      <span className={`score ${scoreClass(pkg.max_vuln_score)}`}>
                        {pkg.max_vuln_score.toFixed(1)}
                      </span>
                    ) : (
                      '—'
                    )}
                  </td>
                  <td className="small nowrap">{formatDate(pkg.published_at)}</td>
                  <td className="small nowrap">{formatDate(pkg.approved_at)}</td>
                  <td>
                    <button
                      className="ghost small"
                      onClick={onToggle}
                    >
                      {selected ? 'скрыть' : 'детали'}
                    </button>
                  </td>
      </tr>
      {selected ? <tr className="details-row"><td colSpan={9}>
        <PackageDetails id={pkg.id} me={me} onChanged={onChanged} embedded />
      </td></tr> : null}
    </>
  )
}

function PackageDetails({ id, me, onChanged, embedded = false }: { id: number; me: Me; onChanged: () => void; embedded?: boolean }) {
  const { data, error, reload } = useAsync(() => api.packageById(id), [id])
  const [reason, setReason] = useState('')
  const [deleteReason, setDeleteReason] = useState('')
  const [actionError, setActionError] = useState<string | null>(null)
  const [deleting, setDeleting] = useState(false)
  const isSec = me.roles.includes('devsecops') || me.roles.includes('admin')
  const isAdmin = me.roles.includes('admin')

  if (error) return <Alert kind="error">{error}</Alert>
  if (!data) return <Loader />

  return (
    <div className={embedded ? 'package-details' : 'card'}>
      {actionError ? <Alert kind="error">{actionError}</Alert> : null}
      <div className="row between">
        <h2 className="mono">
          {data.name} {data.version} <Badge value={data.status} />
        </h2>
        <span className="badge mono">{data.manager}</span>
      </div>

      <dl className="kv" style={{ marginBottom: 10 }}>
        <dt>Лицензия</dt>
        <dd className="mono">
          {data.license_spdx ?? '—'}
          {data.license_source ? <span className="muted"> (источник: {data.license_source})</span> : null}
        </dd>
        <dt>Опубликован в реестре</dt>
        <dd>{formatDate(data.published_at)}</dd>
        {data.quarantine_until ? (
          <>
            <dt>Карантин до</dt>
            <dd>{formatDate(data.quarantine_until)}</dd>
          </>
        ) : null}
        {data.status_reason ? (
          <>
            <dt>Причина статуса</dt>
            <dd>{data.status_reason}</dd>
          </>
        ) : null}
      </dl>

      {data.requests?.length ? (
        <>
          <h3 style={{ marginTop: 12 }}>Связанные заявки</h3>
          <div className="table-scroll"><table>
            <thead>
              <tr>
                <th>Заявка</th>
                <th>Статус пакета</th>
                <th>Автор</th>
                <th>Добавлен</th>
              </tr>
            </thead>
            <tbody>
              {data.requests.map((request) => (
                <tr key={request.request_item_id}>
                  <td>
                    <Link to={`/requests/${request.request_id}`}>
                      заявка #{request.request_id}
                    </Link>
                  </td>
                  <td>
                    <Badge value={request.item_status} title={request.item_status_title} />
                  </td>
                  <td>{request.author ?? '—'}</td>
                  <td className="small nowrap">{formatDate(request.created_at)}</td>
                </tr>
              ))}
            </tbody>
          </table></div>
        </>
      ) : null}

      {data.install_command ? <Copyable command={data.install_command} /> : null}

      {data.vulnerabilities.length ? (
        <>
          <h3 style={{ marginTop: 12 }}>Уязвимости</h3>
          <Vulns items={data.vulnerabilities as never} />
        </>
      ) : null}

      <Artifacts pkg={data} />

      {isSec && data.status === 'approved' ? (
        <div className="row" style={{ marginTop: 12 }}>
          <input
            className="wide"
            placeholder="Причина отзыва (обязательна)"
            value={reason}
            onChange={(e) => setReason(e.target.value)}
          />
          <button
            className="danger small nowrap"
            disabled={!reason.trim()}
            onClick={() =>
              api.revokePackage(data.id, reason).then(() => {
                reload()
                onChanged()
              })
            }
          >
            отозвать пакет
          </button>
        </div>
      ) : null}
      {isAdmin && data.status !== 'deleted' && data.artifacts.some((artifact) => artifact.status === 'published') ? (
        <div className="row destructive-action" style={{ marginTop: 12 }}>
          <input className="wide" placeholder="Причина удаления из внутреннего артефактори (обязательна)"
            value={deleteReason} onChange={(e) => setDeleteReason(e.target.value)} />
          <button className="danger small nowrap" disabled={deleting || deleteReason.trim().length < 3}
            onClick={() => {
              if (!window.confirm(`Удалить ${data.name} ${data.version} из внутреннего артефактори?`)) return
              setDeleting(true); setActionError(null)
              api.deletePackage(data.id, deleteReason.trim())
                .then(() => { reload(); onChanged() })
                .catch((exc: Error) => setActionError(exc.message))
                .finally(() => setDeleting(false))
            }}>{deleting ? 'удаление…' : 'удалить из артефактори'}</button>
        </div>
      ) : null}
    </div>
  )
}

function Artifacts({ pkg }: { pkg: PackageVersion }) {
  if (!pkg.artifacts.length) return null
  return (
    <>
      <h3 style={{ marginTop: 12 }}>Артефакты</h3>
      <div className="table-scroll artifact-table-wrap"><table>
        <thead>
          <tr>
            <th>Файл</th>
            <th>sha256</th>
            <th>Размер</th>
            <th>URL в артефактори</th>
            <th>Промежуточная зона</th>
          </tr>
        </thead>
        <tbody>
          {pkg.artifacts.map((a, i) => (
            <tr key={i}>
              <td className="mono artifact-name">
                {a.nexus_url ? <a href={String(a.nexus_url)} target="_blank" rel="noreferrer">{String(a.filename)}</a> : String(a.filename)}
              </td>
              <td className="mono small">{String(a.sha256 ?? '—').slice(0, 16)}…</td>
              <td className="num">{a.size_bytes ? `${Math.round(Number(a.size_bytes) / 1024)} КБ` : '—'}</td>
              <td className="small">
                {a.nexus_url ? (
                  <a href={String(a.nexus_url)} target="_blank" rel="noreferrer">
                    открыть
                  </a>
                ) : (
                  '—'
                )}
              </td>
              <td className="small dim">
                {a.s3_deleted_at ? 'удалён из временного хранилища' : String(a.s3_key ?? '—')}
              </td>
            </tr>
          ))}
        </tbody>
      </table></div>
    </>
  )
}
