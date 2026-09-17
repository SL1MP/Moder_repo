import { useState } from 'react'
import { Link, useNavigate } from 'react-router-dom'

import { Alert, Badge, Empty, Loader, formatTime, useAsync } from '../components/ui'
import { api, type Me } from '../lib/api'

const STATUS_FILTERS = [
  { value: '', label: 'Все' },
  { value: 'pending', label: 'Проверяются' },
  { value: 'quarantined', label: 'Карантин' },
  { value: 'awaiting_legal', label: 'Ждут юристов' },
  { value: 'awaiting_security', label: 'Ждут DevSecOps' },
  { value: 'approved', label: 'Одобрены' },
  { value: 'rejected', label: 'Отклонены' },
  { value: 'cancelled', label: 'Закрыты автором' },
]

export default function RequestList({ me, scope = 'mine' }: { me: Me; scope?: 'mine' | 'all' }) {
  const [status, setStatus] = useState('')
  const navigate = useNavigate()
  // Чужие заявки видят только эти роли; разработчику переключатель не нужен —
  // API всё равно отдаст ему лишь свои.
  const canSeeAll = me.roles.some((r) => ['admin', 'devsecops', 'legal'].includes(r))
  // Область берётся из маршрута, а не из локального состояния: пункт меню
  // «Мои заявки» обязан показывать именно свои, а не то, что осталось от
  // прошлого переключения.
  const mine = scope === 'mine' || !canSeeAll
  const { data, error, loading, reload } = useAsync(
    () => api.requests({ ...(status ? { status } : {}), mine: String(mine) }),
    [status, mine],
  )

  return (
    <>
      <div className="topbar">
        <div>
          <h1>Заявки на модерацию</h1>
          <p className="page-hint">
            Статус заявки — агрегат по её пакетам. В карточке видно, на каком шаге конвейера
            остановился каждый пакет.
          </p>
          {canSeeAll ? (
            <p className="page-hint">
              {mine
                ? 'Показаны только ваши заявки. Чужие — на вкладке «Все заявки».'
                : 'Показаны заявки всех пользователей.'}
            </p>
          ) : null}
        </div>
        <button className="ghost small" onClick={reload}>
          обновить
        </button>
      </div>

      <div className="card tight row">
        <div className="pill-tabs" style={{ margin: 0 }}>
          {STATUS_FILTERS.map((f) => (
            <button
              key={f.value}
              className={status === f.value ? 'active' : ''}
              onClick={() => setStatus(f.value)}
            >
              {f.label}
            </button>
          ))}
        </div>
        <span className="spacer" />
        {canSeeAll ? (
          <div className="pill-tabs" style={{ margin: 0 }}>
            <button className={mine ? 'active' : ''} onClick={() => navigate('/requests')}>
              Мои заявки
            </button>
            <button className={mine ? '' : 'active'} onClick={() => navigate('/requests/all')}>
              Все заявки
            </button>
          </div>
        ) : null}
      </div>

      {error ? <Alert kind="error">{error}</Alert> : null}
      {loading ? <Loader /> : null}
      {data && !data.length ? <Empty text="Заявок нет" /> : null}

      {data && data.length ? (
        <div className="card">
          <table>
            <thead>
              <tr>
                <th>Заявка</th>
                <th>Менеджер</th>
                <th>Статус</th>
                <th>Пакетов</th>
                <th>Одобрено</th>
                <th>Автор</th>
                <th>Обоснование</th>
                <th>Создана</th>
              </tr>
            </thead>
            <tbody>
              {data.map((row) => (
                <tr key={row.request_id}>
                  <td>
                    <Link to={`/requests/${row.request_id}`}>#{row.request_id}</Link>
                  </td>
                  <td>
                    <span className="badge mono">{row.manager}</span>
                  </td>
                  <td>
                    <Badge value={row.status} title={row.status_title} />
                  </td>
                  <td className="num">{row.total}</td>
                  <td className="num">{row.approved}</td>
                  <td>{row.author ?? '—'}</td>
                  <td className="small dim">{row.reason ?? '—'}</td>
                  <td className="small nowrap">{formatTime(row.created_at)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ) : null}
    </>
  )
}
