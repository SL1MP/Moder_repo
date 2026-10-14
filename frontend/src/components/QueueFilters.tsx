import { useState } from 'react'

import { api, type Manager } from '../lib/api'
import { STATUS_LABELS, useAsync } from './ui'

export interface QueueFilterValue {
  q: string
  manager: Manager | ''
  status: string
}

const EMPTY_FILTERS: QueueFilterValue = { q: '', manager: '', status: '' }

export function QueueFilters({
  value,
  statuses,
  onApply,
}: {
  value: QueueFilterValue
  statuses: string[]
  onApply: (value: QueueFilterValue) => void
}) {
  const [draft, setDraft] = useState(value)
  const managers = useAsync(() => api.managers(), [])

  return (
    <div className="card tight">
      <form
        className="row"
        onSubmit={(event) => {
          event.preventDefault()
          const next = { ...draft, q: draft.q.trim() }
          setDraft(next)
          onApply(next)
        }}
      >
        <label style={{ margin: 0, minWidth: 300, flex: 1 }}>
          <span>Поиск</span>
          <input
            className="wide"
            placeholder="пакет, версия, автор, № заявки или пакета"
            value={draft.q}
            maxLength={200}
            onChange={(event) => setDraft({ ...draft, q: event.target.value })}
          />
        </label>
        <label style={{ margin: 0, minWidth: 150 }}>
          <span>Менеджер</span>
          <select
            value={draft.manager}
            onChange={(event) =>
              setDraft({ ...draft, manager: event.target.value as Manager | '' })
            }
          >
            <option value="">все</option>
            {(managers.data ?? []).map((manager) => (
              <option key={manager.code} value={manager.code}>
                {manager.code}
              </option>
            ))}
          </select>
        </label>
        <label style={{ margin: 0, minWidth: 180 }}>
          <span>Статус в очереди</span>
          <select
            value={draft.status}
            onChange={(event) => setDraft({ ...draft, status: event.target.value })}
          >
            <option value="">все</option>
            {statuses.map((status) => (
              <option key={status} value={status}>
                {STATUS_LABELS[status] ?? status}
              </option>
            ))}
          </select>
        </label>
        <button className="primary small" type="submit" style={{ marginTop: 14 }}>
          применить
        </button>
        <button
          className="ghost small"
          type="button"
          style={{ marginTop: 14 }}
          onClick={() => {
            setDraft(EMPTY_FILTERS)
            onApply(EMPTY_FILTERS)
          }}
        >
          сбросить
        </button>
      </form>
    </div>
  )
}

export function queueFilterParams(value: QueueFilterValue): Record<string, string> {
  return {
    ...(value.q ? { q: value.q } : {}),
    ...(value.manager ? { manager: value.manager } : {}),
    ...(value.status ? { status: value.status } : {}),
  }
}
