#!/usr/bin/env python3
"""Локальный снапшот базы OSV — для запуска сервиса на своей машине.

Зачем. Шаг проверки уязвимостей читает снапшот из каталога OSV_LOCAL_DB_PATH и
НИКОГДА не ходит в сеть сам: решение о пакете принимается по данным, которые
заказчик положил во внутренний репозиторий и может предъявить. В бою снапшот
кладёт туда синхронизация из артефактори (`make sync-osv`). На своей машине
артефактори обычно нет, и без снапшота каждый пакет честно уходит к DevSecOps
с пометкой «снапшот базы OSV ни разу не загружался» — проверить нечем.

Этот скрипт собирает такой снапшот из публичных выгрузок OSV. Он нужен ТОЛЬКО
для локального запуска: в бою источник снапшота — внутренний репозиторий, а не
интернет.

Запуск внутри контейнера (ничего не нужно ставить на хост):

    docker compose run --rm -T -e OSV_ECOSYSTEMS=PyPI \
        --entrypoint python3 worker-go - < scripts/osv_local_snapshot.py

Переменные:
    OSV_ECOSYSTEMS   через пробел: PyPI npm Go NuGet (по умолчанию все четыре)
    OSV_LOCAL_DB_PATH куда класть (по умолчанию /var/lib/osv-db)
"""

from __future__ import annotations

import hashlib
import io
import json
import os
import sys
import urllib.request
import zipfile
from datetime import datetime, timezone
from pathlib import Path

BASE = "https://osv-vulnerabilities.storage.googleapis.com"
# Имена каталогов — те же, что ждёт код (internal/osv.Ecosystems и его
# python-аналог): PyPI, npm, Go, NuGet.
DEFAULT_ECOSYSTEMS = ("PyPI", "npm", "Go", "NuGet")


def fetch(ecosystem: str, root: Path) -> tuple[int, str]:
    """Скачивает и раскладывает выгрузку одной экосистемы. Возвращает (записей, sha256)."""
    url = f"{BASE}/{ecosystem}/all.zip"
    print(f"  {ecosystem}: качаю {url}", flush=True)
    with urllib.request.urlopen(url, timeout=600) as resp:
        payload = resp.read()
    digest = hashlib.sha256(payload).hexdigest()

    target = root / ecosystem
    target.mkdir(parents=True, exist_ok=True)
    count = 0
    with zipfile.ZipFile(io.BytesIO(payload)) as archive:
        for entry in archive.namelist():
            if not entry.endswith(".json") or entry.endswith("/"):
                continue
            # Имя файла без каталогов: код ищет записи обходом каталога
            # экосистемы и различает их по имени файла.
            name = Path(entry).name
            if name == "snapshot.json":
                continue
            (target / name).write_bytes(archive.read(entry))
            count += 1
    print(f"  {ecosystem}: записей {count}", flush=True)
    return count, digest


def main() -> int:
    root = Path(os.environ.get("OSV_LOCAL_DB_PATH", "/var/lib/osv-db"))
    ecosystems = os.environ.get("OSV_ECOSYSTEMS", " ".join(DEFAULT_ECOSYSTEMS)).split()
    root.mkdir(parents=True, exist_ok=True)

    total = 0
    digests = []
    for ecosystem in ecosystems:
        try:
            count, digest = fetch(ecosystem, root)
        except Exception as exc:  # noqa: BLE001 - одна экосистема не должна ронять остальные
            print(f"  {ecosystem}: НЕ загружено ({exc})", file=sys.stderr, flush=True)
            continue
        total += count
        digests.append(digest)

    if not total:
        print("Снапшот не собран: ни одна экосистема не загрузилась.", file=sys.stderr)
        return 1

    now = datetime.now(timezone.utc).replace(microsecond=0)
    # snapshot.json — то, по чему сервис узнаёт версию и возраст базы. Без него
    # каталог с записями считается незагруженным снапшотом, и шаг уязвимостей
    # по-прежнему отдаёт решение DevSecOps.
    meta = {
        "version": now.strftime("local-%Y%m%d"),
        "checksum": hashlib.sha256("".join(digests).encode()).hexdigest(),
        "published_at": now.isoformat().replace("+00:00", "Z"),
        "remote_path": f"local:{BASE}",
        "record_count": total,
    }
    (root / "snapshot.json").write_text(json.dumps(meta, ensure_ascii=False, indent=2))
    print(f"Снапшот собран: {total} записей, версия {meta['version']}, каталог {root}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
