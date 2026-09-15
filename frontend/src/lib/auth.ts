/** OIDC Authorization Code + PKCE к Keycloak и fallback-вход для сервисных учёток. */

import { api, type AuthConfig } from './api'

const STORAGE_KEY = 'moderation.session'
const VERIFIER_KEY = 'moderation.pkce'

export interface Session {
  access_token: string
  refresh_token?: string
  expires_at: number
  kind: 'oidc' | 'local'
}

interface Discovery {
  authorization_endpoint: string
  token_endpoint: string
  end_session_endpoint?: string
}

let discoveryCache: Discovery | null = null

export function loadSession(): Session | null {
  const raw = sessionStorage.getItem(STORAGE_KEY)
  if (!raw) return null
  try {
    const session = JSON.parse(raw) as Session
    return session.expires_at > Date.now() ? session : null
  } catch {
    return null
  }
}

export function saveSession(session: Session) {
  sessionStorage.setItem(STORAGE_KEY, JSON.stringify(session))
}

export function clearSession() {
  sessionStorage.removeItem(STORAGE_KEY)
  sessionStorage.removeItem(VERIFIER_KEY)
}

async function discover(config: AuthConfig): Promise<Discovery> {
  if (discoveryCache) return discoveryCache
  const resp = await fetch(`${config.issuer.replace(/\/$/, '')}/.well-known/openid-configuration`)
  if (!resp.ok) throw new Error('Не удалось получить конфигурацию OIDC-издателя')
  discoveryCache = (await resp.json()) as Discovery
  return discoveryCache
}

function base64url(bytes: Uint8Array): string {
  return btoa(String.fromCharCode(...bytes))
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/, '')
}

async function pkcePair(): Promise<{ verifier: string; challenge: string }> {
  const verifier = base64url(crypto.getRandomValues(new Uint8Array(32)))
  const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(verifier))
  return { verifier, challenge: base64url(new Uint8Array(digest)) }
}

export function redirectUri(): string {
  return `${window.location.origin}/auth/callback`
}

export async function startLogin(config: AuthConfig) {
  const { authorization_endpoint } = await discover(config)
  const { verifier, challenge } = await pkcePair()
  const state = base64url(crypto.getRandomValues(new Uint8Array(16)))
  sessionStorage.setItem(
    VERIFIER_KEY,
    JSON.stringify({ verifier, state, from: window.location.pathname + window.location.search }),
  )
  const params = new URLSearchParams({
    client_id: config.client_id,
    response_type: 'code',
    scope: config.scopes.join(' '),
    redirect_uri: redirectUri(),
    code_challenge: challenge,
    code_challenge_method: 'S256',
    state,
  })
  window.location.assign(`${authorization_endpoint}?${params}`)
}

export async function completeLogin(config: AuthConfig, code: string, state: string): Promise<string> {
  const raw = sessionStorage.getItem(VERIFIER_KEY)
  if (!raw) throw new Error('Сессия входа не найдена, начните вход заново')
  const stored = JSON.parse(raw) as { verifier: string; state: string; from: string }
  if (stored.state !== state) throw new Error('Не совпал параметр state — вход отклонён')

  const { token_endpoint } = await discover(config)
  const resp = await fetch(token_endpoint, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      grant_type: 'authorization_code',
      client_id: config.client_id,
      code,
      redirect_uri: redirectUri(),
      code_verifier: stored.verifier,
    }),
  })
  if (!resp.ok) throw new Error(`Обмен кода на токен не удался (${resp.status})`)
  const payload = (await resp.json()) as {
    access_token: string
    refresh_token?: string
    expires_in: number
  }
  saveSession({
    access_token: payload.access_token,
    refresh_token: payload.refresh_token,
    expires_at: Date.now() + (payload.expires_in - 30) * 1000,
    kind: 'oidc',
  })
  sessionStorage.removeItem(VERIFIER_KEY)
  return stored.from || '/'
}

export async function refresh(config: AuthConfig, session: Session): Promise<Session | null> {
  if (session.kind !== 'oidc' || !session.refresh_token) return null
  const { token_endpoint } = await discover(config)
  const resp = await fetch(token_endpoint, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      grant_type: 'refresh_token',
      client_id: config.client_id,
      refresh_token: session.refresh_token,
    }),
  })
  if (!resp.ok) return null
  const payload = (await resp.json()) as {
    access_token: string
    refresh_token?: string
    expires_in: number
  }
  const next: Session = {
    access_token: payload.access_token,
    refresh_token: payload.refresh_token ?? session.refresh_token,
    expires_at: Date.now() + (payload.expires_in - 30) * 1000,
    kind: 'oidc',
  }
  saveSession(next)
  return next
}

export async function localLogin(username: string, password: string): Promise<Session> {
  const payload = await api.localLogin(username, password)
  const session: Session = {
    access_token: payload.access_token,
    expires_at: Date.now() + (payload.expires_in - 30) * 1000,
    kind: 'local',
  }
  saveSession(session)
  return session
}

export async function logout(config: AuthConfig | null) {
  const session = loadSession()
  clearSession()
  if (config && session?.kind === 'oidc') {
    try {
      const { end_session_endpoint } = await discover(config)
      if (end_session_endpoint) {
        window.location.assign(
          `${end_session_endpoint}?post_logout_redirect_uri=${encodeURIComponent(window.location.origin)}&client_id=${config.client_id}`,
        )
        return
      }
    } catch {
      // издатель недоступен — просто чистим локальную сессию
    }
  }
  window.location.assign('/')
}
