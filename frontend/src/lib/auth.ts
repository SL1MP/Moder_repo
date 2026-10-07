/** Серверная OIDC-сессия и локальная авторизация приложения. */

import { api, type AuthConfig } from './api'

const STORAGE_KEY = 'moderation.session'
const LOGIN_FROM_KEY = 'moderation.login_from'

export interface Session {
  access_token: string
  refresh_token: string
  expires_at: number
  kind: 'oidc' | 'local'
}

export function loadSession(): Session | null {
  const raw = localStorage.getItem(STORAGE_KEY)
  if (!raw) return null
  try {
    const session = JSON.parse(raw) as Session
    if (!session.access_token || !session.refresh_token) return null
    return session
  } catch {
    return null
  }
}

export function saveSession(session: Session) {
  localStorage.setItem(STORAGE_KEY, JSON.stringify(session))
}

export function clearSession() {
  localStorage.removeItem(STORAGE_KEY)
  sessionStorage.removeItem(LOGIN_FROM_KEY)
}

/**
 * Браузер больше не общается с IdP напрямую. Backend создаёт state/nonce/PKCE,
 * кладёт их в подписанную HttpOnly cookie и сам обменивает code на токены.
 */
export function startLogin(config: AuthConfig) {
  if (!config.oidc_enabled || !config.oidc_login_url) {
    return Promise.reject(new Error('Вход через OIDC не настроен администратором'))
  }
  sessionStorage.setItem(LOGIN_FROM_KEY, window.location.pathname + window.location.search)
  window.location.assign(config.oidc_login_url)
  return Promise.resolve()
}

/** Принимает только внутреннюю пару токенов, которую backend вернул во fragment. */
export function completeLogin(): string {
  const fragment = new URLSearchParams(window.location.hash.replace(/^#/, ''))
  const access = fragment.get('access_token')
  const refreshToken = fragment.get('refresh_token')
  const expiresIn = Number(fragment.get('expires_in') || 900)
  if (!access || !refreshToken) {
    throw new Error(fragment.get('error') || 'Backend не вернул токены приложения')
  }
  saveSession({
    access_token: access,
    refresh_token: refreshToken,
    expires_at: Date.now() + Math.max(expiresIn - 30, 30) * 1000,
    kind: 'oidc',
  })
  const from = sessionStorage.getItem(LOGIN_FROM_KEY) || '/'
  sessionStorage.removeItem(LOGIN_FROM_KEY)
  return from.startsWith('/') ? from : '/'
}

export async function refresh(_config: AuthConfig, session: Session): Promise<Session | null> {
  if (!session.refresh_token) return null
  try {
    const payload = await api.refreshSession(session.refresh_token)
    const next: Session = {
      access_token: payload.access_token,
      refresh_token: payload.refresh_token,
      expires_at: Date.now() + Math.max(payload.expires_in - 30, 30) * 1000,
      kind: session.kind,
    }
    saveSession(next)
    return next
  } catch {
    return null
  }
}

export async function localLogin(username: string, password: string): Promise<Session> {
  const payload = await api.localLogin(username, password)
  const session: Session = {
    access_token: payload.access_token,
    refresh_token: payload.refresh_token,
    expires_at: Date.now() + Math.max(payload.expires_in - 30, 30) * 1000,
    kind: 'local',
  }
  saveSession(session)
  return session
}

export function logout(_config: AuthConfig | null) {
  clearSession()
  window.location.assign('/')
}
