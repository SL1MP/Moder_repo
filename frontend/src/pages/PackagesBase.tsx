import { useState } from 'react'
import { useSearchParams } from 'react-router-dom'

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
  '',
  'approved',
  'quarantined',
  'awaiting_legal',
  'awaiting_security',
  'rejected',
  'revoked',
  'blacklisted',
]

export default function PackagesBase({ me }: { me: Me }) {
  const [params, setParams] = useSearchParams()
  const [query, setQuery] = useState(params.get('q') ?? '')
  const [manager, setManager] = useState<Manager | ''>('')
  const [version, setVersion] = useState('')
  const [status, setStatus] = useState(params.get('status') ?? '')
  const [selected, setSelected] = useState<number | null>(null)

  const { data, error, loading, reload } = useAsync(
    () =>
      api.packages({
        ...(query ? { q: query } : {}),
        ...(manager ? { manager } : {}),
        ...(version ? { version } : {}),
        ...(status ? { status } : {}),
        limit: '100',
      }),
    [query, manager, version, status],
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
              <option value="pypi">pypi</option>
              <option value="npm">npm</option>
              <option value="go">go</option>
              <option value="nuget">nuget</option>
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
                <option key={s} value={s}>
                  {s || 'все'}
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
          <table>
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
                <tr key={pkg.id}>
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
                      onClick={() => setSelected(selected === pkg.id ? null : pkg.id)}
                    >
                      {selected === pkg.id ? 'скрыть' : 'детали'}
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ) : null}

      {selected ? <PackageDetails id={selected} me={me} onChanged={reload} /> : null}
    </>
  )
}

function PackageDetails({ id, me, onChanged }: { id: number; me: Me; onChanged: () => void }) {
  const { data, error, reload } = useAsync(() => api.packageById(id), [id])
  const [reason, setReason] = useState('')
  const isSec = me.roles.includes('devsecops') || me.roles.includes('admin')

  if (error) return <Alert kind="error">{error}</Alert>
  if (!data) return <Loader />

  return (
    <div className="card">
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
    </div>
  )
}

function Artifacts({ pkg }: { pkg: PackageVersion }) {
  if (!pkg.artifacts.length) return null
  return (
    <>
      <h3 style={{ marginTop: 12 }}>Артефакты</h3>
      <table>
        <thead>
          <tr>
            <th>Файл</th>
            <th>sha256</th>
            <th>Размер</th>
            <th>URL в артефактори</th>
            <th>MinIO</th>
          </tr>
        </thead>
        <tbody>
          {pkg.artifacts.map((a, i) => (
            <tr key={i}>
              <td className="mono">{String(a.filename)}</td>
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
      </table>
    </>
  )
}
