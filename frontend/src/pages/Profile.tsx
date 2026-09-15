import { useState } from 'react'
import { Link } from 'react-router-dom'

import { Alert, Empty, Loader, formatTime, useAsync } from '../components/ui'
import { api, type AuthConfig, type Me } from '../lib/api'

const ROLE_TITLES: Record<string, string> = {
  admin: 'администратор — всё, включая аудит-лог и перечитывание конфигурации',
  devsecops: 'DevSecOps — решения по уязвимостям и карантину, все заявки',
  legal: 'юрист — решения по лицензиям, все заявки',
  developer: 'разработчик — свои заявки, чтение базы пакетов, обсуждения',
}

export default function Profile({ me, config }: { me: Me; config: AuthConfig }) {
  const notifications = useAsync(() => api.notifications(), [])
  const gitlab = useAsync(() => api.gitlabStatus(), [])
  const [error, setError] = useState<string | null>(null)

  return (
    <>
      <div className="topbar">
        <div>
          <h1>Профиль</h1>
          <p className="page-hint">
            Роли приходят из групп каталога через SSO и маппятся переменными{' '}
            <code>ROLE_MAPPING_*</code>.
          </p>
        </div>
      </div>

      {error ? <Alert kind="error">{error}</Alert> : null}

      <div className="grid cols-2">
        <div className="card">
          <h2>{me.display_name}</h2>
          <dl className="kv">
            <dt>Логин</dt>
            <dd className="mono">{me.username}</dd>
            <dt>Email</dt>
            <dd>{me.email ?? '—'}</dd>
            <dt>Тип учётной записи</dt>
            <dd>{me.is_service ? 'сервисная' : 'пользовательская'}</dd>
            <dt>Issuer</dt>
            <dd className="mono small">{config.issuer}</dd>
          </dl>
          <h3 style={{ marginTop: 10 }}>Роли</h3>
          {me.roles.length ? (
            <ul style={{ margin: 0, paddingLeft: 18 }}>
              {me.roles.map((role) => (
                <li key={role} className="small">
                  <b>{role}</b> — {ROLE_TITLES[role] ?? 'роль сервиса'}
                </li>
              ))}
            </ul>
          ) : (
            <Alert kind="warn">
              У учётной записи нет ролей сервиса. Проверьте членство в группах каталога:{' '}
              {Object.values(config.role_mapping).join(', ')}.
            </Alert>
          )}
        </div>

        <div className="card">
          <h2>GitLab</h2>
          <p className="small dim">
            Доступ только на чтение (<code>read_repository</code>): сервис читает файлы зависимостей
            из ваших приватных проектов. Ничего не коммитим и merge request'ы не открываем.
          </p>
          {!config.gitlab_enabled ? (
            <Alert kind="info">
              Интеграция не настроена: задайте <code>GITLAB_URL</code> и OAuth-параметры в{' '}
              <code>.env</code>.
            </Alert>
          ) : gitlab.loading ? (
            <Loader />
          ) : gitlab.data?.connected ? (
            <>
              <dl className="kv">
                <dt>Учётная запись</dt>
                <dd className="mono">{String(gitlab.data.gitlab_username ?? '—')}</dd>
                <dt>Токен действителен до</dt>
                <dd>{formatTime((gitlab.data.expires_at as string) ?? null)}</dd>
                <dt>Scopes</dt>
                <dd className="mono small">{String(gitlab.data.scopes ?? '')}</dd>
              </dl>
              <button
                className="danger small"
                onClick={() => api.gitlabDisconnect().then(() => gitlab.reload())}
              >
                отключить GitLab
              </button>
            </>
          ) : (
            <button
              className="primary small"
              onClick={() =>
                api
                  .gitlabAuthorize()
                  .then((res) => window.location.assign(res.authorize_url))
                  .catch((exc: Error) => setError(exc.message))
              }
            >
              подключить GitLab
            </button>
          )}
        </div>
      </div>

      <div className="card">
        <div className="row between">
          <h2>Уведомления {notifications.data?.unread ? `(${notifications.data.unread} новых)` : ''}</h2>
          <div className="row">
            <button
              className="small"
              disabled={!notifications.data?.unread}
              onClick={() => api.markRead([]).then(() => notifications.reload())}
            >
              отметить все прочитанными
            </button>
            <button className="ghost small" onClick={notifications.reload}>
              обновить
            </button>
          </div>
        </div>
        {notifications.error ? <Alert kind="error">{notifications.error}</Alert> : null}
        {notifications.loading ? <Loader /> : null}
        {notifications.data && !notifications.data.items.length ? (
          <Empty text="Уведомлений нет" />
        ) : null}
        {notifications.data?.items.length ? (
          <table>
            <tbody>
              {notifications.data.items.map((n) => (
                <tr key={n.id}>
                  <td className="nowrap small">{formatTime(n.created_at)}</td>
                  <td>
                    {n.read_at ? null : <span className="badge warn">новое</span>}{' '}
                    <b>{n.title}</b>
                    {n.body ? <div className="small dim">{n.body}</div> : null}
                  </td>
                  <td className="nowrap">
                    {n.request_id ? (
                      <Link to={`/requests/${n.request_id}`}>заявка #{n.request_id}</Link>
                    ) : (
                      <span className="muted">—</span>
                    )}
                  </td>
                  <td className="nowrap">
                    {n.read_at ? (
                      <span className="muted small">прочитано</span>
                    ) : (
                      <button
                        className="ghost small"
                        onClick={() => api.markRead([n.id]).then(() => notifications.reload())}
                      >
                        прочитано
                      </button>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        ) : null}
      </div>
    </>
  )
}
