import { useState } from 'react'

import { Alert, Loader, formatTime, useAsync } from '../components/ui'
import { api, type Me } from '../lib/api'

export default function SettingsPage({ me }: { me: Me }) {
  const settings = useAsync(() => api.settings(), [])
  const policies = useAsync(() => api.policies(), [])
  const system = useAsync(() => api.systemStatus(), [])
  const [message, setMessage] = useState<string | null>(null)
  const [error, setError] = useState<string | null>(null)
  const isAdmin = me.roles.includes('admin')
  const isSec = me.roles.includes('devsecops') || isAdmin

  const sections = new Map<string, typeof settings.data>()
  for (const row of settings.data ?? []) {
    const list = sections.get(row.section) ?? []
    list.push(row)
    sections.set(row.section, list as never)
  }

  return (
    <>
      <div className="topbar">
        <div>
          <h1>Настройка</h1>
          <p className="page-hint">
            Только чтение. Все политики и адреса задаются переменными окружения и применяются при
            старте: правка <code>.env</code> + рестарт. Blacklist и справочник лицензий — файлы
            конфигурации, их можно перечитать без рестарта.
          </p>
        </div>
        {isAdmin ? (
          <button
            className="small"
            onClick={() => {
              setError(null)
              api
                .reloadConfig()
                .then((res) => {
                  setMessage(
                    `Перечитано: blacklist — ${res.blacklist?.rules} правил, лицензии — ` +
                      `${res.licenses?.allowed} разрешено / ${res.licenses?.forbidden} запрещено`,
                  )
                  policies.reload()
                })
                .catch((exc: Error) => setError(exc.message))
            }}
          >
            перечитать конфигурацию
          </button>
        ) : null}
      </div>

      {message ? <Alert kind="ok">{message}</Alert> : null}
      {error ? <Alert kind="error">{error}</Alert> : null}
      {settings.error ? <Alert kind="error">{settings.error}</Alert> : null}
      {settings.loading ? <Loader /> : null}

      {system.data ? <QueueCard info={system.data} isAdmin={isAdmin} onDone={() => system.reload()} /> : null}

      {policies.data?.vuln_index ? <VulnIndexCard info={policies.data.vuln_index} isSec={isSec} /> : null}

      {[...sections.entries()].map(([section, rows]) => (
        <div className="card" key={section}>
          <h2>{section}</h2>
          <table>
            <thead>
              <tr>
                <th>Переменная</th>
                <th>Значение</th>
                <th>Описание</th>
              </tr>
            </thead>
            <tbody>
              {(rows ?? []).map((row) => (
                <tr key={row.env}>
                  <td className="mono nowrap">{row.env}</td>
                  <td className="mono small">
                    {row.secret ? (
                      <span className="muted">{String(row.value)}</span>
                    ) : (
                      String(row.value ?? '—') || <span className="muted">пусто</span>
                    )}
                  </td>
                  <td className="small dim">{row.description}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ))}

      {policies.data?.blacklist ? (
        <div className="card">
          <h2>Blacklist</h2>
          <p className="small dim">
            Файл <code>{policies.data.blacklist.path}</code>, загружен{' '}
            {formatTime(policies.data.blacklist.loaded_at)}. Совпадение останавливает конвейер на
            шаге 1 — пакет не скачивается.
          </p>
          {policies.data.blacklist.error ? (
            <Alert kind="warn">Файл не загружен: {policies.data.blacklist.error}</Alert>
          ) : null}
          <table>
            <thead>
              <tr>
                <th>Менеджер</th>
                <th>Имя / glob</th>
                <th>Версии</th>
                <th>Причина</th>
                <th>Добавил</th>
              </tr>
            </thead>
            <tbody>
              {(policies.data.blacklist.rules ?? []).map((rule: Record<string, string>, i: number) => (
                <tr key={i}>
                  <td className="mono">{rule.manager ?? 'любой'}</td>
                  <td className="mono">{rule.name}</td>
                  <td className="mono">{rule.versions}</td>
                  <td className="small dim">{rule.reason}</td>
                  <td className="small">
                    {rule.added_by ?? '—'} {rule.added_at ? `· ${rule.added_at}` : ''}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ) : null}

      {policies.data?.licenses ? (
        <div className="card">
          <h2>Справочник лицензий (SPDX)</h2>
          <p className="small dim">
            Файл <code>{policies.data.licenses.path}</code>, загружен{' '}
            {formatTime(policies.data.licenses.loaded_at)}.
          </p>
          <div className="grid cols-2">
            <div>
              <h3>Разрешены</h3>
              <div className="row">
                {(policies.data.licenses.allowed ?? []).map((l: Record<string, string>) => (
                  <span className="badge mono pass" key={l.spdx_id} title={l.notes ?? ''}>
                    {l.spdx_id}
                  </span>
                ))}
              </div>
            </div>
            <div>
              <h3>Запрещены</h3>
              <div className="row">
                {(policies.data.licenses.forbidden ?? []).map((l: Record<string, string>) => (
                  <span className="badge mono fail" key={l.spdx_id} title={l.notes ?? ''}>
                    {l.spdx_id}
                  </span>
                ))}
              </div>
            </div>
          </div>
        </div>
      ) : null}
    </>
  )
}

function QueueCard({
  info,
  isAdmin,
  onDone,
}: {
  info: Record<string, any>
  isAdmin: boolean
  onDone: () => void
}) {
  const [message, setMessage] = useState<string | null>(null)
  const worker = info.worker ?? {}
  const watchdog = info.watchdog ?? {}
  const stuck = Number(info.queue?.stuck_items ?? 0)
  const alive = Boolean(worker.alive)

  return (
    <div className="card">
      <div className="row between">
        <h2>Обработка очереди</h2>
        {isAdmin ? (
          <button
            className="small"
            onClick={() =>
              api
                .sweepQueue()
                .then((res) => {
                  setMessage(
                    `Проход сторожа: зависших — ${res.stuck}, подхвачено — ${res.recovered}` +
                      (res.mode === 'inline' ? ' (выполнено на месте, worker молчит)' : ''),
                  )
                  onDone()
                })
                .catch((exc: Error) => setMessage(exc.message))
            }
          >
            разобрать очередь сейчас
          </button>
        ) : null}
      </div>
      {message ? <Alert kind="info">{message}</Alert> : null}
      {!alive ? (
        <Alert kind="warn">
          Celery-worker не отвечает: {String(worker.detail)}. Пакеты не остановятся — их подхватит
          сторож в процессе API, но проверки будут идти медленнее. Поднимите контейнер{' '}
          <code>worker</code>.
        </Alert>
      ) : null}
      {stuck > 0 ? (
        <Alert kind="warn">
          Пакетов, висящих в очереди дольше {String(watchdog.stuck_after_seconds)} с: {stuck}.
          Сторож заберёт их в ближайший проход.
        </Alert>
      ) : null}
      <dl className="kv">
        <dt>Celery worker</dt>
        <dd>
          <span className={alive ? 'badge pass' : 'badge fail'}>
            {alive ? 'разбирает очередь' : 'не отвечает'}
          </span>
        </dd>
        <dt>Последний heartbeat</dt>
        <dd>{formatTime((worker.last_seen as string) ?? null)}</dd>
        <dt>Зависших пакетов</dt>
        <dd className="mono">{stuck}</dd>
        <dt>Сторож очереди</dt>
        <dd>
          {watchdog.enabled
            ? `включён, проход раз в ${String(watchdog.interval_seconds)} с`
            : 'выключен (PIPELINE_WATCHDOG_ENABLED=false)'}
        </dd>
      </dl>
    </div>
  )
}

function VulnIndexCard({ info, isSec }: { info: Record<string, unknown>; isSec: boolean }) {
  const [message, setMessage] = useState<string | null>(null)
  const stale = Boolean(info.stale)

  return (
    <div className="card">
      <div className="row between">
        <h2>База уязвимостей OSV</h2>
        {isSec ? (
          <button
            className="small"
            onClick={() =>
              api
                .syncOsv()
                .then((res) => setMessage(`Синхронизация: ${JSON.stringify(res)}`))
                .catch((exc: Error) => setMessage(exc.message))
            }
          >
            синхронизировать снапшот
          </button>
        ) : null}
      </div>
      {message ? <Alert kind="info">{message}</Alert> : null}
      {stale ? (
        <Alert kind="warn">
          Снапшот устарел или не загружен — автоматическое одобрение отключено: шаг 5 даёт{' '}
          <code>warn</code> и требует решения DevSecOps.
        </Alert>
      ) : null}
      <dl className="kv">
        <dt>Источник</dt>
        <dd className="mono">{String(info.source)}</dd>
        <dt>Версия снапшота</dt>
        <dd className="mono">{String(info.version ?? 'не загружен')}</dd>
        <dt>Дата снапшота</dt>
        <dd>{formatTime((info.published_at as string) ?? null)}</dd>
        <dt>Записей</dt>
        <dd>{String(info.record_count ?? '—')}</dd>
        <dt>Возраст</dt>
        <dd>
          {info.age_days !== null && info.age_days !== undefined
            ? `${Number(info.age_days).toFixed(1)} дн (допустимо ${String(info.max_staleness_days)})`
            : '—'}
        </dd>
      </dl>
    </div>
  )
}
