"""Проверка OIDC-токенов Keycloak: подпись по JWKS и допустимые issuer'ы.

Ключевой сценарий: браузер получает токен по внешнему адресу Keycloak
(`OIDC_PUBLIC_ISSUER`, например http://localhost:8081/realms/moderation), а API
забирает JWKS по внутреннему (`OIDC_ISSUER`, http://keycloak:8080/realms/moderation).
`iss` в токене при этом внешний, подпись — одна и та же, и токен должен приниматься.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

import pytest
import respx
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from jose import jwk, jwt

from app.core.config import get_settings
from app.core.errors import AuthError
from app.core.security import decode_token, reset_jwks_cache, sync_user

INTERNAL_ISSUER = "http://keycloak:8080/realms/moderation"
PUBLIC_ISSUER = "http://localhost:8081/realms/moderation"
CERTS_URL = f"{INTERNAL_ISSUER}/protocol/openid-connect/certs"


def _rsa_keypair() -> tuple[str, str]:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    private_pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode()
    public_pem = key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode()
    return private_pem, public_pem


@dataclass
class FakeKeycloak:
    """Подменный Keycloak: выдаёт подписанные токены и отдаёт свой JWKS."""

    private_pem: str
    jwks: dict[str, object]

    def make_token(
        self, *, issuer: str = PUBLIC_ISSUER, groups: list[str] | None = None, **extra
    ) -> str:
        now = datetime.now(UTC)
        payload = {
            "iss": issuer,
            "sub": "e5f0b2d1-1111-2222-3333-444455556666",
            "preferred_username": "dev.ivanov",
            "email": "dev.ivanov@example.com",
            "name": "Иван Иванов",
            "azp": "moderation-web",
            "iat": int(now.timestamp()),
            "exp": int((now + timedelta(minutes=30)).timestamp()),
            "groups": groups if groups is not None else ["moderation-developer"],
            **extra,
        }
        return jwt.encode(payload, self.private_pem, algorithm="RS256", headers={"kid": "test-key"})

    def mock(self, router: respx.Router):
        """Регистрирует discovery и JWKS по внутреннему адресу; возвращает маршрут JWKS."""
        router.get(f"{INTERNAL_ISSUER}/.well-known/openid-configuration").respond(
            json={"issuer": INTERNAL_ISSUER, "jwks_uri": CERTS_URL}
        )
        return router.get(CERTS_URL).respond(
            content=json.dumps(self.jwks), headers={"Content-Type": "application/json"}
        )


@pytest.fixture
def keycloak(monkeypatch) -> FakeKeycloak:
    s = get_settings()
    monkeypatch.setattr(s, "oidc_issuer", INTERNAL_ISSUER)
    monkeypatch.setattr(s, "oidc_public_issuer", PUBLIC_ISSUER)
    reset_jwks_cache()

    private_pem, public_pem = _rsa_keypair()
    entry = jwk.construct(public_pem, algorithm="RS256").to_dict()
    entry = {k: (v.decode() if isinstance(v, bytes) else v) for k, v in entry.items()}
    entry.update({"kid": "test-key", "use": "sig", "alg": "RS256"})

    yield FakeKeycloak(private_pem=private_pem, jwks={"keys": [entry]})
    reset_jwks_cache()


def test_token_from_public_issuer_is_accepted(keycloak):
    """Основной сценарий входа через браузер: iss внешний, JWKS берётся по внутреннему."""
    with respx.mock(assert_all_called=False) as mock:
        keycloak.mock(mock)
        claims = decode_token(keycloak.make_token(issuer=PUBLIC_ISSUER))

    assert claims.username == "dev.ivanov"
    assert claims.roles == ["developer"]  # группа moderation-developer -> роль developer


def test_token_from_internal_issuer_is_accepted(keycloak):
    """Сервисный клиент внутри docker-сети получает токен с внутренним iss."""
    with respx.mock(assert_all_called=False) as mock:
        keycloak.mock(mock)
        claims = decode_token(keycloak.make_token(issuer=INTERNAL_ISSUER))
    assert claims.username == "dev.ivanov"


def test_token_from_foreign_issuer_is_rejected(keycloak):
    with respx.mock(assert_all_called=False) as mock:
        keycloak.mock(mock)
        with pytest.raises(AuthError, match="не прошёл проверку"):
            decode_token(keycloak.make_token(issuer="http://evil.example.com/realms/moderation"))


def test_expired_token_is_rejected(keycloak):
    now = datetime.now(UTC)
    with respx.mock(assert_all_called=False) as mock:
        keycloak.mock(mock)
        with pytest.raises(AuthError, match="не прошёл проверку"):
            decode_token(
                keycloak.make_token(
                    exp=int((now - timedelta(minutes=5)).timestamp()),
                    iat=int((now - timedelta(minutes=40)).timestamp()),
                )
            )


def test_token_signed_by_other_key_is_rejected(keycloak):
    """Токен, подписанный чужим ключом, не проходит проверку по JWKS."""
    other = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    other_pem = other.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode()
    now = datetime.now(UTC)
    forged = jwt.encode(
        {
            "iss": PUBLIC_ISSUER,
            "sub": "attacker",
            "preferred_username": "attacker",
            "exp": int((now + timedelta(minutes=30)).timestamp()),
        },
        other_pem,
        algorithm="RS256",
        headers={"kid": "test-key"},
    )
    with respx.mock(assert_all_called=False) as mock:
        keycloak.mock(mock)
        with pytest.raises(AuthError, match="не прошёл проверку"):
            decode_token(forged)


@pytest.mark.parametrize(
    ("groups", "expected"),
    [
        (["moderation-admin"], ["admin"]),
        (["moderation-devsecops"], ["devsecops"]),
        (["moderation-legal"], ["legal"]),
        (["moderation-developer"], ["developer"]),
        (["/moderation-developer"], ["developer"]),  # full path из Keycloak
        (["moderation-admin", "moderation-developer"], ["admin", "developer"]),
        (["unrelated-group"], []),
    ],
)
def test_group_to_role_mapping(keycloak, groups, expected):
    with respx.mock(assert_all_called=False) as mock:
        keycloak.mock(mock)
        claims = decode_token(keycloak.make_token(groups=groups))
    assert claims.roles == expected


def test_roles_from_realm_access(keycloak):
    """Keycloak может отдавать роли в realm_access, а не в groups."""
    with respx.mock(assert_all_called=False) as mock:
        keycloak.mock(mock)
        claims = decode_token(
            keycloak.make_token(groups=[], realm_access={"roles": ["moderation-devsecops"]})
        )
    assert claims.roles == ["devsecops"]


def test_sync_user_creates_then_updates(session, keycloak):
    with respx.mock(assert_all_called=False) as mock:
        keycloak.mock(mock)
        claims = decode_token(keycloak.make_token())
        user = sync_user(session, claims)
        session.commit()
        assert user.username == "dev.ivanov"
        assert user.roles == ["developer"]
        first_id = user.id

        # Повторный вход тем же субъектом не создаёт второго пользователя, роли обновляются.
        promoted = decode_token(keycloak.make_token(groups=["moderation-admin"]))
        again = sync_user(session, promoted)
        session.commit()

    assert again.id == first_id
    assert again.roles == ["admin"]


def test_jwks_is_cached_between_calls(keycloak):
    """JWKS не запрашивается на каждый токен — иначе Keycloak получает лишнюю нагрузку."""
    with respx.mock(assert_all_called=False) as mock:
        certs = keycloak.mock(mock)
        decode_token(keycloak.make_token())
        decode_token(keycloak.make_token())
        assert certs.call_count == 1


def test_unknown_realm_gives_clear_message(keycloak):
    """Если realm не импортировался, ошибка должна называть причину, а не быть глухим 500."""
    with respx.mock(assert_all_called=False) as mock:
        mock.get(f"{INTERNAL_ISSUER}/.well-known/openid-configuration").respond(
            404, json={"error": "Realm does not exist"}
        )
        with pytest.raises(AuthError, match="Проверьте OIDC_ISSUER"):
            decode_token(keycloak.make_token())


def test_non_json_from_issuer_gives_clear_message(keycloak):
    """Вместо JSON пришла HTML-страница (прокси/балансировщик) — не должно быть 500."""
    with respx.mock(assert_all_called=False) as mock:
        mock.get(f"{INTERNAL_ISSUER}/.well-known/openid-configuration").respond(
            200, text="<html><body>Gateway</body></html>", headers={"Content-Type": "text/html"}
        )
        with pytest.raises(AuthError, match="вернул не JSON"):
            decode_token(keycloak.make_token())


def test_missing_oidc_issuer_is_reported(keycloak, monkeypatch):
    from app.core.errors import ConfigurationError

    monkeypatch.setattr(get_settings(), "oidc_issuer", "")
    reset_jwks_cache()
    with pytest.raises(ConfigurationError, match="OIDC_ISSUER"):
        decode_token(keycloak.make_token())
