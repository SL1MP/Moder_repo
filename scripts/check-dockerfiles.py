#!/usr/bin/env python3
"""Проверка Dockerfile'ов без docker-демона.

Ловит класс ошибок, который иначе всплывает только при сборке на боевой машине:
Docker завершает инструкцию на переносе строки, и многострочный аргумент без
обратного слэша в конце каждой строки превращается в «unknown instruction».
Один раз на этом уже сломалась сборка Keycloak.
"""

from __future__ import annotations

import sys
from pathlib import Path

INSTRUCTIONS = {
    "ADD", "ARG", "CMD", "COPY", "ENTRYPOINT", "ENV", "EXPOSE", "FROM",
    "HEALTHCHECK", "LABEL", "MAINTAINER", "ONBUILD", "RUN", "SHELL",
    "STOPSIGNAL", "USER", "VOLUME", "WORKDIR",
}
SKIP_DIRS = {"node_modules", ".venv", ".git", "dist"}


def check(path: Path) -> list[str]:
    problems: list[str] = []
    continuation = False
    for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        stripped = line.strip()
        if not continuation and stripped and not stripped.startswith("#"):
            word = stripped.split(maxsplit=1)[0].upper()
            if word not in INSTRUCTIONS:
                problems.append(
                    f"{path}:{number}: строка не начинается с инструкции Dockerfile "
                    f"({stripped[:60]!r}). Похоже на продолжение предыдущей строки — "
                    f"добавьте `\\` в конец предыдущей."
                )
        continuation = stripped.endswith("\\") and not stripped.startswith("#")
    return problems


def main() -> int:
    root = Path(sys.argv[1]) if len(sys.argv) > 1 else Path(".")
    found: list[str] = []
    checked = 0
    for path in sorted(root.rglob("Dockerfile")):
        if SKIP_DIRS & set(path.parts):
            continue
        checked += 1
        found.extend(check(path))

    for problem in found:
        print(problem, file=sys.stderr)
    if found:
        print(f"\nПроблем: {len(found)} в {checked} файлах", file=sys.stderr)
        return 1
    print(f"Dockerfile'ы в порядке ({checked} шт.)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
