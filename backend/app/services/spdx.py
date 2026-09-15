"""Нормализация лицензий к SPDX-идентификаторам."""

from __future__ import annotations

import re

# Частые написания в метаданных реестров → канонический SPDX-идентификатор.
_ALIASES: dict[str, str] = {
    "mit": "MIT",
    "mit license": "MIT",
    "the mit license": "MIT",
    "apache 2.0": "Apache-2.0",
    "apache-2.0": "Apache-2.0",
    "apache license 2.0": "Apache-2.0",
    "apache software license": "Apache-2.0",
    "apache license, version 2.0": "Apache-2.0",
    "bsd": "BSD-3-Clause",
    "bsd license": "BSD-3-Clause",
    "bsd-3-clause": "BSD-3-Clause",
    "new bsd license": "BSD-3-Clause",
    "bsd 3-clause": "BSD-3-Clause",
    "bsd-2-clause": "BSD-2-Clause",
    "simplified bsd": "BSD-2-Clause",
    "isc": "ISC",
    "isc license": "ISC",
    "mpl-2.0": "MPL-2.0",
    "mozilla public license 2.0": "MPL-2.0",
    "gpl-2.0": "GPL-2.0-only",
    "gplv2": "GPL-2.0-only",
    "gpl-3.0": "GPL-3.0-only",
    "gplv3": "GPL-3.0-only",
    "lgpl-2.1": "LGPL-2.1-only",
    "lgpl-3.0": "LGPL-3.0-only",
    "agpl-3.0": "AGPL-3.0-only",
    "unlicense": "Unlicense",
    "the unlicense": "Unlicense",
    "cc0-1.0": "CC0-1.0",
    "python-2.0": "Python-2.0",
    "psf": "Python-2.0",
    "psf-2.0": "Python-2.0",
    "zlib": "Zlib",
    "artistic-2.0": "Artistic-2.0",
    "ms-pl": "MS-PL",
    "proprietary": "LicenseRef-Proprietary",
}

_SPDX_RE = re.compile(r"^[A-Za-z0-9.+\-]+$")
_CLASSIFIER_RE = re.compile(r"^License :: (?:OSI Approved :: )?(?P<name>.+)$")

_CLASSIFIER_MAP: dict[str, str] = {
    "mit license": "MIT",
    "apache software license": "Apache-2.0",
    "bsd license": "BSD-3-Clause",
    "isc license (iscl)": "ISC",
    "mozilla public license 2.0 (mpl 2.0)": "MPL-2.0",
    "gnu general public license v2 (gplv2)": "GPL-2.0-only",
    "gnu general public license v3 (gplv3)": "GPL-3.0-only",
    "gnu lesser general public license v2 (lgplv2)": "LGPL-2.1-only",
    "gnu lesser general public license v3 (lgplv3)": "LGPL-3.0-only",
    "gnu affero general public license v3": "AGPL-3.0-only",
    "python software foundation license": "Python-2.0",
    "the unlicense (unlicense)": "Unlicense",
    "zope public license": "ZPL-2.1",
}


def normalize_spdx(value: str | None) -> str | None:
    """Приводит строку лицензии к SPDX-идентификатору; None — если не определилась."""
    if not value:
        return None
    text = " ".join(value.strip().split())
    if not text or len(text) > 200:
        return None  # длинный текст лицензии вместо идентификатора
    lowered = text.lower()
    if lowered in {"unknown", "none", "unlicensed", "see license", "other/proprietary license"}:
        return None
    if lowered in _ALIASES:
        return _ALIASES[lowered]
    # Составные выражения (`MIT OR Apache-2.0`) оставляем как есть.
    if re.search(r"\b(or|and|with)\b", lowered) and _looks_like_expression(text):
        return text
    if _SPDX_RE.match(text):
        return text
    return None


def _looks_like_expression(text: str) -> bool:
    tokens = [t for t in re.split(r"\s+", text) if t.upper() not in {"OR", "AND", "WITH"}]
    return bool(tokens) and all(_SPDX_RE.match(t.strip("()")) for t in tokens)


def spdx_from_classifiers(classifiers: list[str]) -> str | None:
    """Достаёт лицензию из classifiers PyPI, если поле license пустое."""
    for classifier in classifiers:
        m = _CLASSIFIER_RE.match(classifier.strip())
        if not m:
            continue
        name = m.group("name").strip()
        mapped = _CLASSIFIER_MAP.get(name.lower())
        if mapped:
            return mapped
        direct = normalize_spdx(name)
        if direct:
            return direct
    return None
