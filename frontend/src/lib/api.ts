/** Клиент REST API сервиса модерации. */

const API = '/api/v1'

export class ApiError extends Error {
  code: string
  status: number
  details: unknown
  retryAfter: number | null

  constructor(
    status: number,
    code: string,
    message: string,
    details?: unknown,
    retryAfter: number | null = null,
  ) {
    super(message)
    this.status = status
    this.code = code
    this.details = details
    this.retryAfter = retryAfter
  }
}

let tokenGetter: () => string | null = () => null
let onUnauthorized: () => void = () => {}

export function configureApi(getToken: () => string | null, unauthorized: () => void) {
  tokenGetter = getToken
  onUnauthorized = unauthorized
}

async function request<T>(path: string, init: RequestInit = {}): Promise<T> {
  const headers = new Headers(init.headers)
  headers.set('X-Client', 'web')
  if (!(init.body instanceof FormData) && init.body) headers.set('Content-Type', 'application/json')
  const token = tokenGetter()
  if (token) headers.set('Authorization', `Bearer ${token}`)

  // API содержит быстро меняющиеся статусы конвейера. Даже ручное «обновить»
  // не должно получить сохранённый браузером GET-ответ.
  const resp = await fetch(path.startsWith('/api') ? path : `${API}${path}`, {
    ...init,
    headers,
    cache: init.cache ?? 'no-store',
  })
  if (resp.status === 204) return undefined as T

  const text = await resp.text()
  let payload: {
    error?: { code?: string; message?: string; details?: unknown; request_id?: string }
  } | null = null
  try {
    payload = text ? JSON.parse(text) : null
  } catch {
    payload = null // не JSON (например, ответ прокси или nginx)
  }

  if (!resp.ok) {
    const err = payload?.error
    // Сообщение сервера сохраняем как есть: в нём причина отказа (истёкший токен,
    // неверный пароль, не совпал issuer). Затирать его общим текстом — значит
    // прятать от пользователя единственную полезную диагностику.
    // request_id дописываем к тексту: сервер в сообщении просит сообщить его
    // администратору, но без вывода на экран указание невыполнимо — по логам
    // ошибку тогда не найти.
    const base = err?.message ?? `Ошибка запроса (${resp.status})`
    const message = err?.request_id ? `${base} (request_id: ${err.request_id})` : base
    const retryAfterHeader = resp.headers.get('Retry-After')
    const retryAfter = retryAfterHeader ? Number.parseInt(retryAfterHeader, 10) : Number.NaN
    const retryAfterSeconds = Number.isFinite(retryAfter) && retryAfter > 0 ? retryAfter : null
    if (resp.status === 401) {
      // Провал входа на самой форме не должен сбрасывать сессию: сессии ещё нет,
      // а onUnauthorized() увёл бы пользователя с формы, не показав причину.
      if (!path.startsWith('/auth/token')) onUnauthorized()
      throw new ApiError(401, err?.code ?? 'unauthorized', message, err?.details)
    }
    throw new ApiError(
      resp.status,
      err?.code ?? 'http_error',
      message,
      err?.details,
      retryAfterSeconds,
    )
  }
  return payload as T
}

// fetchFile — загрузка файла по защищённому маршруту с токеном.
//
// Зачем отдельно от request(): отчёт это не JSON-ответ API, а файл, и ссылкой
// его не открыть. Браузер по обычному <a href> заголовок Authorization НЕ
// отправляет, поэтому ссылка на защищённый маршрут отвечала 401 — ровно это и
// происходило с кнопками «смотреть» и «JSON» у отчётов сканирования.
export async function fetchFile(url: string): Promise<{ body: string; contentType: string }> {
  const headers = new Headers({ 'X-Client': 'web' })
  const token = tokenGetter()
  if (token) headers.set('Authorization', `Bearer ${token}`)

  const resp = await fetch(url, { headers })
  const body = await resp.text()
  if (!resp.ok) {
    let message = `Ошибка запроса (${resp.status})`
    try {
      const payload = JSON.parse(body) as {
        error?: { message?: string; code?: string; request_id?: string }
      }
      if (payload.error?.message) {
        message = payload.error.request_id
          ? `${payload.error.message} (request_id: ${payload.error.request_id})`
          : payload.error.message
      }
      if (resp.status === 401) onUnauthorized()
      throw new ApiError(resp.status, payload.error?.code ?? 'http_error', message)
    } catch (e) {
      if (e instanceof ApiError) throw e
      throw new ApiError(resp.status, 'http_error', message)
    }
  }
  return { body, contentType: resp.headers.get('Content-Type') ?? '' }
}

// --------------------------------------------------------------------------- типы
// Список кодов держать 1:1 с domain.ManagerCodes на бэкенде. Тип нужен для
// подсказок редактора; сам список менеджеров интерфейс всегда получает
// запросом /managers, а не отсюда — зашитый в интерфейс перечень молча
// отстаёт от бэкенда.
export type Manager =
  | 'pypi'
  | 'npm'
  | 'go'
  | 'nuget'
  | 'conan'
  | 'docker'
  | 'luarocks'
  | 'maven'
  | 'php'
  | 'terraform'
  | 'git'
  | 'files'

export interface ManagerInfo {
  code: Manager
  title: string
  entry_format: string
  dependency_files: string[]
  osv_ecosystem: string
}

export interface Me {
  id: number
  username: string
  display_name: string
  email: string | null
  roles: string[]
  is_service: boolean
  gitlab_connected: boolean
}

export interface AuthConfig {
  issuer: string
  client_id: string
  scopes: string[]
  flow: string
  local_auth_enabled: boolean
  app_name: string
  app_env: string
  gitlab_enabled: boolean
  role_mapping: Record<string, string>
}

export interface Step {
  code: string
  order: number
  title: string
  // info — шаг выполнен, публикацию не блокирует (SAST), см. STEP_RESULT_LABELS
  result: 'pending' | 'pass' | 'info' | 'warn' | 'fail' | 'skipped'
  message: string | null
  details: Record<string, unknown> | null
  started_at: string | null
  finished_at: string | null
}

export interface Vulnerability {
  id: string
  score: number
  cvss_vector: string | null
  severity: string | null
  url: string | null
  summary: string | null
  fixed_versions: string[] | null
}

/** Находка сканера содержимого: политический баннер (yara) или SAST (semgrep). */
export interface CodeFinding {
  scanner: string
  rule_id: string
  severity: string
  message: string | null
  file: string | null
  line: number | null
  matched: string | null
}

/**
 * Отчёт о прогоне сканера содержимого. Отдаётся Go-версией backend'а
 * (`/api/v1/request-items/{id}/reports`), python-версия отчётов не формирует.
 *
 * `state` — три значения, и путать их нельзя:
 *   clean       — сканер отработал, срабатываний выше порога нет;
 *   findings    — есть срабатывания, нужно решение DevSecOps;
 *   unavailable — проверка НЕ выполнена. Это не «чисто».
 */
export interface ScanReport {
  step_code: string
  step_title: string
  scanner: string
  rules?: string
  state: 'clean' | 'findings' | 'unavailable'
  state_title: string
  threshold: string
  findings_total: number
  findings_blocking: number
  worst_severity?: string
  detail?: string
  duration_ms?: number
  created_at: string
  json_url: string
  html_url: string
}

export interface ScanReportList {
  request_item_id: number
  reports: ScanReport[]
}

export interface RequestItem {
  id: number
  package_version_id: number
  name: string
  version: string
  dependency_kind: string
  // Дерево зависимостей внутри заявки: кто притащил этот пакет и по какому
  // требованию. У заявленного напрямую depth === 0 и родителя нет.
  depth: number
  parent_item_id?: number
  required_range?: string
  status: string
  status_title: string
  /**
   * Шаги, по которым решение роли ещё не получено: `license` — юристы,
   * `vuln_scan` — DevSecOps, `quarantine` — срок карантина. Их может быть
   * несколько сразу, поэтому статуса (он один) для интерфейса недостаточно:
   * более блокирующий скрыл бы блок второй роли.
   */
  pending: string[]
  current_step: string | null
  current_step_title: string | null
  blocked_reason: string | null
  next_action: string | null
  waiting_since: string | null
  finished_at: string | null
  license_spdx: string | null
  quarantine_until: string | null
  max_vuln_score: number | null
  install_command?: string | null
  vulnerabilities: Vulnerability[]
  code_findings: CodeFinding[]
  steps: Step[]
}

export interface ModerationRequest {
  request_id: number
  manager: Manager
  status: string
  status_title: string
  approved: boolean
  // Можно ли закрыть заявку прямо сейчас и именно этому пользователю. Считает
  // сервер: правило одно и то же с маршрутом, и дублировать его здесь значило
  // бы завести второй источник правды.
  can_cancel: boolean
  author: string | null
  author_role: string | null
  reason: string | null
  source: string
  origin_file: string | null
  include_transitive: boolean
  // Итог раскрытия: до какой глубины разошлись и что вышло. Нужен, чтобы
  // объяснить обрезанное дерево — неполное выглядит как полное.
  resolve_depth: number | null
  resolve_summary: string | null
  warnings: string[]
  created_at: string
  updated_at: string
  summary: {
    total: number
    approved: number
    awaiting_security: number
    awaiting_legal: number
    quarantined: number
    rejected: number
    failed: number
    cancellable: number
    cancelled: number
    by_status: Record<string, number>
  }
  packages: RequestItem[]
}

export interface RequestListRow {
  request_id: number
  manager: Manager
  status: string
  status_title: string
  author: string | null
  reason: string | null
  created_at: string
  total: number
  approved: number
}

export interface ParsedPackage {
  raw: string
  state: 'new' | 'already_in_base' | 'invalid_format'
  name: string | null
  version: string | null
  dependency_kind: string
  // Дерево зависимостей: 0 — заявленный пакет, дальше — кто его потребовал и
  // по какому требованию выбрана версия.
  depth?: number
  required_by?: string
  required_range?: string
  message: string | null
  expected_format?: string
  package_version_id?: number
  status?: string
  link?: string
  install_command?: string
}

export interface CreateRequestResult {
  request_id: number
  manager: Manager
  status: string
  accepted: number
  skipped_already_in_base: number
  invalid: number
  warnings: string[]
  packages: ParsedPackage[]
  status_url: string
}

// DependencyTree — предпросмотр: что заявка потянет за собой, до её создания.
export interface DependencyTree {
  manager: Manager
  packages: ParsedPackage[]
  direct: number
  transitive: number
  warnings: string[]
  limits: { max_depth: number; max_packages: number }
  // resolved === false означает «менеджер так не умеет», а не «зависимостей
  // нет»: пустое дерево в этих двух случаях выглядит одинаково.
  resolved: boolean
  depth?: number
  truncated?: boolean
  summary?: string
  registry_requests?: number
  problems?: {
    name: string
    constraint: string
    required_by: string
    depth: number
    reason: string
  }[]
  conflicts?: { name: string; versions: string[] }[]
}

export interface PackageVersion {
  id: number
  manager: Manager
  name: string
  normalized_name: string
  version: string
  status: string
  license_spdx: string | null
  license_source: string | null
  published_at: string | null
  quarantine_until: string | null
  approved_at: string | null
  max_vuln_score: number | null
  status_reason: string | null
  install_command?: string | null
  vulnerabilities: Record<string, unknown>[]
  artifacts: Record<string, unknown>[]
}

export interface QueueItem {
  item_id: number
  request_id: number
  manager: Manager
  name: string
  version: string
  status: string
  status_title: string
  current_step: string | null
  blocked_reason: string | null
  waiting_since: string | null
  waiting_hours: number | null
  author: string | null
  license_spdx: string | null
  max_vuln_score: number | null
  license_claim_id: number | null
}

export interface Comment {
  id: number
  request_id: number
  request_item_id: number | null
  author: string
  author_role: string | null
  body: string
  mentions: string[]
  is_edited: boolean
  edited_at: string | null
  deleted: boolean
  created_at: string
  can_edit: boolean
}

export interface Notification {
  id: number
  event: string
  title: string
  body: string | null
  request_id: number | null
  request_item_id: number | null
  created_at: string
  read_at: string | null
}

export interface LicenseClaim {
  id: number
  package_version_id: number
  request_item_id: number | null
  package: string | null
  version: string | null
  manager: Manager | null
  url: string
  spdx_id: string | null
  comment: string | null
  status: string
  snapshot_text: string | null
  snapshot_fetched_at: string | null
  claimed_by: string | null
  decided_by: string | null
  decided_at: string | null
  decision_comment: string | null
  created_at: string
  suggested_license: { spdx_id: string; confirmed_for_version: string; note: string } | null
}

export interface SettingRow {
  env: string
  section: string
  description: string
  value: unknown
  secret: boolean
}

export interface AuditRow {
  id: number
  actor_name: string
  actor_role: string | null
  action: string
  entity_type: string
  entity_id: string | null
  old_value: unknown
  new_value: unknown
  source: string
  source_title: string | null
  comment: string | null
  ip: string | null
  created_at: string
}

// --------------------------------------------------------------------------- вызовы
export const api = {
  authConfig: () => request<AuthConfig>('/auth/config'),
  me: () => request<Me>('/auth/me'),
  localLogin: (username: string, password: string) =>
    request<{ access_token: string; expires_in: number; roles: string[] }>('/auth/token', {
      method: 'POST',
      body: JSON.stringify({ username, password }),
    }),

  managers: () => request<ManagerInfo[]>('/managers'),
  detectManager: (filename: string) =>
    request<{ filename: string; manager: Manager | null }>(
      `/managers/detect?filename=${encodeURIComponent(filename)}`,
    ),

  resolveDependencies: (body: {
    manager: Manager
    packages: string[]
    depth?: number
    include_optional?: boolean
  }) => request<DependencyTree>('/dependencies/resolve', { method: 'POST', body: JSON.stringify(body) }),

  createRequest: (
    body: {
      manager: Manager
      packages: string[]
      reason?: string
      include_transitive?: boolean
      resolve_depth?: number
    },
    idempotencyKey?: string,
  ) =>
    request<CreateRequestResult>('/requests', {
      method: 'POST',
      body: JSON.stringify(body),
      headers: idempotencyKey ? { 'Idempotency-Key': idempotencyKey } : undefined,
    }),

  createRequestFromFile: (form: FormData) =>
    request<CreateRequestResult>('/requests', { method: 'POST', body: form }),

  createRequestFromGitlab: (body: {
    project: string
    path: string
    ref: string
    manager?: Manager | null
    reason?: string
    include_transitive: boolean
  }) => request<CreateRequestResult>('/gitlab/requests', { method: 'POST', body: JSON.stringify(body) }),

  requests: (params: Record<string, string> = {}) =>
    request<RequestListRow[]>(`/requests?${new URLSearchParams(params)}`),
  requestById: (id: number) => request<ModerationRequest>(`/requests/${id}`),
  retryRequest: (id: number) => request<ModerationRequest>(`/requests/${id}/retry`, { method: 'POST' }),
  // Закрытие заявки автором: пакеты больше не нужны. Не отклонение — то
  // решение роли, а это отказ автора.
  cancelRequest: (id: number) =>
    request<ModerationRequest>(`/requests/${id}/cancel`, { method: 'POST' }),

  packages: (params: Record<string, string>) =>
    request<{ total: number; limit: number; offset: number; items: PackageVersion[] }>(
      `/packages?${new URLSearchParams(params)}`,
    ),
  packageById: (id: number) => request<PackageVersion>(`/packages/${id}`),
  checkPackages: (manager: Manager, packages: string[]) =>
    request<{ manager: Manager; packages: Record<string, unknown>[] }>('/packages/check', {
      method: 'POST',
      body: JSON.stringify({ manager, packages }),
    }),
  revokePackage: (id: number, comment: string) =>
    request<{ status: string }>(`/packages/${id}/revoke`, {
      method: 'POST',
      body: JSON.stringify({ approve: false, comment }),
    }),

  queueSecurity: () => request<QueueItem[]>('/queue/security'),
  queueLegal: () => request<QueueItem[]>('/queue/legal'),
  queueCounters: () => request<Record<string, number>>('/queue/counters'),

  /**
   * Отчёты о сканировании по пакету заявки.
   *
   * Отдаёт их Go-версия; если она не поднята, nginx вернёт 502, а если
   * сканирование не запускалось — пустой список. Ни то ни другое не должно
   * ронять карточку заявки, поэтому вызывающий код обрабатывает ошибку
   * отдельно и мягко.
   */
  scanReports: (itemId: number) =>
    request<ScanReportList>(`/request-items/${itemId}/reports`),

  releaseQuarantine: (itemId: number, comment: string) =>
    request<RequestItem>(`/items/${itemId}/quarantine/release`, {
      method: 'POST',
      body: JSON.stringify({ comment }),
    }),
  securityDecision: (itemId: number, approve: boolean, comment: string) =>
    request<RequestItem>(`/items/${itemId}/security-decision`, {
      method: 'POST',
      body: JSON.stringify({ approve, comment }),
    }),
  claimLicense: (itemId: number, body: { url: string; spdx_id?: string; comment?: string }) =>
    request<LicenseClaim>(`/items/${itemId}/license-claim`, {
      method: 'POST',
      body: JSON.stringify(body),
    }),
  licenseClaims: (status = 'pending') => request<LicenseClaim[]>(`/license-claims?status=${status}`),
  licenseClaim: (id: number) => request<LicenseClaim>(`/license-claims/${id}`),
  decideLicense: (id: number, approve: boolean, comment: string) =>
    request<LicenseClaim>(`/license-claims/${id}/decision`, {
      method: 'POST',
      body: JSON.stringify({ approve, comment }),
    }),
  licenses: () =>
    request<{
      allowed: { spdx_id: string; name: string | null }[]
      forbidden: { spdx_id: string; name: string | null }[]
    }>('/licenses'),

  comments: (requestId: number, itemId?: number) =>
    request<Comment[]>(
      `/requests/${requestId}/comments${itemId ? `?request_item_id=${itemId}` : ''}`,
    ),
  addComment: (requestId: number, body: string, itemId?: number | null) =>
    request<Comment>(`/requests/${requestId}/comments`, {
      method: 'POST',
      body: JSON.stringify({ body, request_item_id: itemId ?? null }),
    }),
  editComment: (id: number, body: string) =>
    request<Comment>(`/comments/${id}`, { method: 'PATCH', body: JSON.stringify({ body }) }),
  deleteComment: (id: number) => request<Comment>(`/comments/${id}`, { method: 'DELETE' }),

  notifications: (onlyUnread = false) =>
    request<{ unread: number; items: Notification[] }>(
      `/notifications?only_unread=${onlyUnread}`,
    ),
  markRead: (ids: number[]) =>
    request<{ updated: number }>('/notifications/read', {
      method: 'POST',
      body: JSON.stringify({ ids, all: ids.length === 0 }),
    }),

  settings: () => request<SettingRow[]>('/settings'),
  policies: () => request<Record<string, any>>('/settings/policies'),
  reloadConfig: () => request<Record<string, any>>('/admin/reload', { method: 'POST' }),
  systemStatus: () => request<Record<string, any>>('/system/status'),
  sweepQueue: () => request<Record<string, any>>('/admin/queue-sweep', { method: 'POST' }),
  audit: (params: Record<string, string> = {}) =>
    request<AuditRow[]>(`/admin/audit?${new URLSearchParams(params)}`),
  osvVersions: () => request<Record<string, unknown>[]>('/admin/osv-versions'),
  syncOsv: () => request<Record<string, unknown>>('/admin/osv-sync', { method: 'POST' }),

  gitlabStatus: () => request<Record<string, unknown>>('/gitlab/status'),
  gitlabAuthorize: () => request<{ authorize_url: string; state: string }>('/gitlab/authorize'),
  gitlabDisconnect: () => request<{ connected: boolean }>('/gitlab/connection', { method: 'DELETE' }),
}
