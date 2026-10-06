import { Link } from 'react-router-dom'

import { Alert, Loader, useAsync } from '../components/ui'
import { api, type ManagerInfo, type Me } from '../lib/api'

const MANAGER_MARKS: Record<string, string> = {
  pypi: 'Py', npm: 'npm', go: 'Go', nuget: '.NET', conan: 'C++', docker: 'OCI',
  luarocks: 'Lua', maven: 'M', php: 'PHP', terraform: 'TF', git: 'Git', files: 'File',
}

export default function Home({ me }: { me: Me }) {
  const managers = useAsync(() => api.managers(), [])

  return (
    <>
      <section className="hero">
        <div>
          <span className="eyebrow">Единая точка доверия к зависимостям</span>
          <h1>Модерация пакетов</h1>
          <p>
            Сервис проверяет происхождение, карантин, лицензию и безопасность артефакта,
            формирует SBOM и публикует одобренную версию во внутренний Nexus.
          </p>
        </div>
        <div className="hero-status">
          <span className="status-dot" />
          <div><strong>{me.display_name}</strong><small>{me.roles.join(', ') || 'роль ещё не назначена'}</small></div>
        </div>
      </section>

      {!me.roles.length ? (
        <Alert kind="warn">
          Keycloak подтвердил вашу личность, но роль внутри сервиса ещё не назначена.
          Обратитесь к администратору — после назначения повторный вход не требуется.
        </Alert>
      ) : null}

      <div className="section-heading">
        <div>
          <h2>Выберите экосистему</h2>
          <p className="page-hint">Откроется форма с форматом записи и файлами именно этого менеджера.</p>
        </div>
        <Link className="text-link" to="/packages">Перейти в базу пакетов →</Link>
      </div>

      {managers.error ? <Alert kind="error">{managers.error}</Alert> : null}
      {managers.loading ? <Loader /> : null}
      <div className="manager-grid">
        {(managers.data ?? []).map((manager) => <ManagerTile key={manager.code} manager={manager} />)}
      </div>

      <section className="how-it-works">
        <h2>Как это работает</h2>
        <div className="flow-grid">
          <Flow number="01" title="Найдите пакет" text="Сервис сначала проверит внутреннюю базу и не создаст дубль." />
          <Flow number="02" title="Создайте заявку" text="Укажите версии списком, файлом зависимостей или ссылкой на GitLab." />
          <Flow number="03" title="Дождитесь проверок" text="Все этапы и требуемые решения ролей видны в карточке заявки." />
          <Flow number="04" title="Установите из Nexus" text="После одобрения сервис покажет готовую команду с публичным адресом." />
        </div>
      </section>
    </>
  )
}

function ManagerTile({ manager }: { manager: ManagerInfo }) {
  return (
    <Link className="manager-tile" to={`/add?manager=${encodeURIComponent(manager.code)}`}>
      <span className={`manager-mark manager-${manager.code}`}>{MANAGER_MARKS[manager.code] ?? manager.code}</span>
      <span className="manager-copy">
        <strong>{manager.title}</strong>
        <small>{manager.entry_format}</small>
      </span>
      <span className="manager-arrow">→</span>
    </Link>
  )
}

function Flow({ number, title, text }: { number: string; title: string; text: string }) {
  return <div className="flow-card"><span>{number}</span><strong>{title}</strong><p>{text}</p></div>
}
