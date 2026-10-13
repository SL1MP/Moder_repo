#!/usr/bin/env python3
"""Build a small, reproducible load-test catalogue from public registries."""

from __future__ import annotations

import json
import os
import pathlib
import urllib.parse
import urllib.request
from datetime import datetime, timedelta, timezone


OUTPUT = pathlib.Path(__file__).with_name("requests.json")
USER_AGENT = "moder-repo-loadtest-dataset/1.0"


def get_json(url: str) -> dict:
    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    with urllib.request.urlopen(request, timeout=30) as response:
        return json.load(response)


def docker_packages(repository: str, count: int) -> list[dict[str, str]]:
    url = (
        "https://hub.docker.com/v2/repositories/library/"
        f"{urllib.parse.quote(repository)}/tags?page_size=100"
    )
    result: list[dict[str, str]] = []
    seen: set[str] = set()
    quarantine_days = int(os.environ.get("LOADTEST_QUARANTINE_DAYS", "14"))
    # В нагрузочном наборе нужны валидные для сервиса версии, а не `latest` и
    # экспериментальные каналы, и они должны быть старше карантина. Иначе
    # тест измеряет ожидаемую политическую остановку, а не производительность.
    cutoff = datetime.now(timezone.utc) - timedelta(days=max(quarantine_days, 0) + 1)

    while url and len(result) < count:
        payload = get_json(url)
        for tag in payload.get("results", []):
            name = str(tag.get("name", "")).strip()
            digest = str(tag.get("digest", "")).strip()
            media_type = str(tag.get("media_type", ""))
            updated_raw = str(tag.get("last_updated", "")).strip()

            # Для Docker-модерации нужен digest индекса, а не manifest digest
            # одной платформы.
            if not name or not digest.startswith("sha256:"):
                continue
            if name.lower() in {"latest", "edge", "unstable"}:
                continue
            if "unstable" in name.lower() or "edge" in name.lower():
                continue
            try:
                updated = datetime.fromisoformat(updated_raw.replace("Z", "+00:00"))
            except ValueError:
                continue
            if updated > cutoff:
                continue
            if "image.index" not in media_type and "manifest.list" not in media_type:
                continue

            version = f"{name}@{digest}"
            if version in seen:
                continue
            seen.add(version)
            result.append({"manager": "docker", "name": repository, "version": version})
            if len(result) == count:
                break

        url = payload.get("next")

    if len(result) != count:
        raise RuntimeError(
            f"Docker Hub вернул для library/{repository} только {len(result)} "
            f"multi-platform тегов вместо {count}"
        )
    return result


def main() -> None:
    packages: list[dict[str, str]] = []

    # 54% — Docker, как в корпоративной статистике. Теги берутся вместе с
    # актуальным index digest непосредственно из Docker Hub.
    packages.extend(docker_packages("alpine", 27))
    packages.extend(docker_packages("busybox", 27))

    # Проверенные выпущенные версии; намеренно не используем prerelease.
    packages.extend(
        {"manager": "npm", "name": name, "version": version}
        for name, version in [
            ("lodash", "4.17.21"),
            ("express", "4.21.2"),
            ("axios", "1.7.9"),
            ("react", "18.3.1"),
            ("react-dom", "18.3.1"),
            ("typescript", "5.7.3"),
            ("vite", "5.4.14"),
            ("zod", "3.24.1"),
            ("chalk", "5.4.1"),
            ("commander", "13.1.0"),
            ("dotenv", "16.4.7"),
            ("uuid", "11.0.5"),
            ("dayjs", "1.11.13"),
            ("rxjs", "7.8.1"),
            ("semver", "7.6.3"),
            ("ajv", "8.17.1"),
            ("fastify", "5.2.1"),
            ("winston", "3.17.0"),
        ]
    )

    packages.extend(
        {"manager": "pypi", "name": name, "version": version}
        for name, version in [
            ("requests", "2.32.3"),
            ("urllib3", "2.3.0"),
            ("certifi", "2024.12.14"),
            ("idna", "3.10"),
            ("charset-normalizer", "3.4.1"),
            ("pydantic", "2.10.6"),
            ("fastapi", "0.115.6"),
            ("starlette", "0.41.3"),
            ("click", "8.1.8"),
            ("packaging", "24.2"),
            ("jinja2", "3.1.5"),
            ("markupsafe", "3.0.2"),
            ("pyyaml", "6.0.2"),
            ("six", "1.17.0"),
            ("aenum", "3.1.15"),
        ]
    )

    packages.extend(
        {"manager": "go", "name": name, "version": version}
        for name, version in [
            ("github.com/stretchr/testify", "v1.10.0"),
            ("github.com/google/uuid", "v1.6.0"),
            ("github.com/spf13/cobra", "v1.8.1"),
            ("github.com/prometheus/client_golang", "v1.20.5"),
            ("golang.org/x/sync", "v0.10.0"),
            ("golang.org/x/crypto", "v0.32.0"),
        ]
    )

    packages.extend(
        {"manager": "maven", "name": name, "version": version}
        for name, version in [
            ("org.apache.commons:commons-lang3", "3.17.0"),
            ("com.google.guava:guava", "33.4.0-jre"),
            ("com.fasterxml.jackson.core:jackson-databind", "2.18.2"),
            ("org.slf4j:slf4j-api", "2.0.16"),
            ("org.junit.jupiter:junit-jupiter", "5.11.4"),
        ]
    )

    packages.append(
        {"manager": "nuget", "name": "Newtonsoft.Json", "version": "13.0.3"}
    )
    packages.append({"manager": "conan", "name": "zlib", "version": "1.3.1"})

    if len(packages) != 100:
        raise RuntimeError(f"Ожидалось 100 записей, сформировано {len(packages)}")

    keys = {(item["manager"], item["name"], item["version"]) for item in packages}
    if len(keys) != len(packages):
        raise RuntimeError("В наборе обнаружены повторяющиеся manager/name/version")

    OUTPUT.write_text(
        json.dumps(packages, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    print(f"Создан {OUTPUT}: {len(packages)} пакетов")


if __name__ == "__main__":
    main()
