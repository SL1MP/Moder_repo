import { useState } from 'react'

import { Alert, Empty, Loader, formatTime, useAsync } from '../components/ui'
import { api } from '../lib/api'

const ACTION_LABELS: Record<string, string> = {
  request_created: 'создана заявка',
  request_retried: 'перезапуск заявки',
  pipeline_resumed: 'конвейер возобновлён',
  quarantine_released: 'карантин снят',
  quarantine_released_early: 'карантин снят досрочно',
  security_approved: 'DevSecOps разрешил',
  security_rejected: 'DevSecOps отклонил',
  license_claimed: 'заявлена лицензия',
  license_approved: 'лицензия подтверждена',
  license_rejected: 'лицензия отклонена',
  package_revoked: 'пакет отозван',
  package_imported: 'импорт пакета',
  comment_added: 'сообщение в обсуждении',
  comment_edited: 'сообщение изменено',
  comment_deleted: 'сообщение удалено',
  config_reloaded: 'конфигурация перечитана',
  queue_swept: 'очередь разобрана вручную',
  osv_snapshot_synced: 'снапшот OSV загружен',
  osv_sync_triggered: 'запрошена синхронизация OSV',
  s3_orphans_cleaned: 'очистка временного хранилища',
  gitlab_connected: 'GitLab подключён',
  gitlab_disconnected: 'GitLab отключён',
  local_login: 'вход по логину',
  local_login_failed: 'неудачный вход',
  service_account_created: 'создана сервисная учётка',
  demo_data_seeded: 'загружены демо-данные',
}

export default function Audit() {
  const [action, setAction] = useState('')
  const [entityType, setEntityType] = useState('')
  const [actor, setActor] = useState('')
  const { data, error, loading, reload } = useAsync(
    () =>
      api.audit({
        ...(action ? { action } : {}),
        ...(entityType ? { entity_type: entityType } : {}),
        ...(actor ? { actor } : {}),
        limit: '200',
      }),
    [action, entityType, actor],
  )

  return (
    <>
      <div className="topbar">
        <div>
          <h1>Аудит-лог</h1>
          <p className="page-hint">
            Каждое действие: кто, что, когда, старое и новое значение, источник (UI / REST API /
            фоновая задача / CLI).
          </p>
        </div>
        <button className="ghost small" onClick={reload}>
          обновить
        </button>
      </div>

      <div className="card tight row">
        <label style={{ margin: 0 }}>
          <span>Действие</span>
          <select value={action} onChange={(e) => setAction(e.target.value)}>
            <option value="">все</option>
            {Object.entries(ACTION_LABELS).map(([key, label]) => (
              <option key={key} value={key}>
                {label}
              </option>
            ))}
          </select>
        </label>
        <label style={{ margin: 0 }}>
          <span>Сущность</span>
          <select value={entityType} onChange={(e) => setEntityType(e.target.value)}>
            <option value="">все</option>
            <option value="moderation_request">заявка</option>
            <option value="request_item">пакет заявки</option>
            <option value="package_version">версия пакета</option>
            <option value="license_claim">заявление лицензии</option>
            <option value="comment">сообщение</option>
            <option value="configuration">конфигурация</option>
            <option value="vuln_index_version">снапшот OSV</option>
            <option value="user">пользователь</option>
          </select>
        </label>
        <label style={{ margin: 0 }}>
          <span>Автор действия</span>
          <input value={actor} onChange={(e) => setActor(e.target.value)} placeholder="логин" />
        </label>
      </div>

      {error ? <Alert kind="error">{error}</Alert> : null}
      {loading ? <Loader /> : null}
      {data && !data.length ? <Empty text="Записей нет" /> : null}

      {data && data.length ? (
        <div className="card">
          <table>
            <thead>
              <tr>
                <th>Когда</th>
                <th>Кто</th>
                <th>Действие</th>
                <th>Объект</th>
                <th>Было → стало</th>
                <th>Источник</th>
              </tr>
            </thead>
            <tbody>
              {data.map((row) => (
                <tr key={row.id}>
                  <td className="small nowrap">{formatTime(row.created_at)}</td>
                  <td className="nowrap">
                    {row.actor_name}
                    {row.actor_role ? <span className="badge">{row.actor_role}</span> : null}
                  </td>
                  <td className="small">{ACTION_LABELS[row.action] ?? row.action}</td>
                  <td className="small mono nowrap">
                    {row.entity_type}
                    {row.entity_id ? `#${row.entity_id}` : ''}
                  </td>
                  <td className="small mono" style={{ maxWidth: 420, overflowWrap: 'anywhere' }}>
                    {row.old_value ? <div className="muted">{JSON.stringify(row.old_value)}</div> : null}
                    {row.new_value ? <div>{JSON.stringify(row.new_value)}</div> : null}
                    {row.comment ? <div className="dim">{row.comment}</div> : null}
                  </td>
                  <td className="small nowrap">
                    {row.source_title ?? row.source}
                    {row.ip ? <div className="muted">{row.ip}</div> : null}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ) : null}
    </>
  )
}
