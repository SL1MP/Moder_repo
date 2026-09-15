"""Шифрование чувствительных данных (refresh-токены GitLab) — Fernet, ключ из .env."""

from __future__ import annotations

from cryptography.fernet import Fernet, InvalidToken

from app.core.config import get_settings
from app.core.errors import ConfigurationError


def _fernet() -> Fernet:
    key = get_settings().fernet_key
    if not key:
        raise ConfigurationError(
            "Не задан FERNET_KEY — шифрование токенов GitLab невозможно. "
            'Сгенерируйте: python -c "from cryptography.fernet import Fernet;'
            'print(Fernet.generate_key().decode())"'
        )
    try:
        return Fernet(key.encode() if isinstance(key, str) else key)
    except (ValueError, TypeError) as exc:
        raise ConfigurationError("FERNET_KEY имеет неверный формат (ожидается base64, 32 байта)") from exc


def encrypt(value: str) -> str:
    return _fernet().encrypt(value.encode()).decode()


def decrypt(value: str) -> str:
    try:
        return _fernet().decrypt(value.encode()).decode()
    except InvalidToken as exc:
        raise ConfigurationError("Не удалось расшифровать токен: ключ FERNET_KEY изменён") from exc
