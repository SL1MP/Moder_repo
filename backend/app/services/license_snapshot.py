"""Снапшот текста лицензии по ссылке, приложенной разработчиком.

Юрист смотрит на этот текст, принимая решение, поэтому важно, чтобы он был
читаемым. Ссылку обычно берут из браузера — а это страница репозитория
(`github.com/owner/repo/blob/main/LICENSE`), которая отдаёт целый HTML-документ.
Раньше он сохранялся как есть, и в карточке вместо текста лицензии
показывалась разметка вперемешку со скриптами.

Здесь две вещи: ссылка на страницу просмотра переводится в ссылку на сырой
файл, а если ответ всё равно оказался HTML — из него вынимается текст.
"""

from __future__ import annotations

import re
from html import unescape
from html.parser import HTMLParser
from urllib.parse import urlsplit, urlunsplit

# Теги, содержимое которых в текст лицензии попадать не должно.
_SKIP_CONTENT = {"script", "style", "noscript", "template", "svg", "head"}
# Теги, на которых имеет смысл переносить строку.
_BREAK_AFTER = {"p", "br", "div", "li", "tr", "h1", "h2", "h3", "h4", "h5", "h6", "pre", "article"}


class _TextExtractor(HTMLParser):
    """Вытаскивает видимый текст. Без внешних зависимостей — задача простая."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.parts: list[str] = []
        self._skip_depth = 0

    def handle_starttag(self, tag: str, attrs) -> None:
        if tag in _SKIP_CONTENT:
            self._skip_depth += 1
        elif tag in _BREAK_AFTER:
            self.parts.append("\n")

    def handle_endtag(self, tag: str) -> None:
        if tag in _SKIP_CONTENT and self._skip_depth:
            self._skip_depth -= 1
        elif tag in _BREAK_AFTER:
            self.parts.append("\n")

    def handle_data(self, data: str) -> None:
        if not self._skip_depth:
            self.parts.append(data)

    def text(self) -> str:
        return "".join(self.parts)


def looks_like_html(body: str, content_type: str = "") -> bool:
    if "html" in content_type.lower():
        return True
    head = body.lstrip()[:400].lower()
    return head.startswith("<!doctype html") or head.startswith("<html") or "<body" in head


def html_to_text(body: str) -> str:
    parser = _TextExtractor()
    try:
        parser.feed(body)
        parser.close()
    except Exception:  # noqa: BLE001 - на битой разметке отдаём хоть что-то
        return collapse_blank_lines(unescape(re.sub(r"<[^>]+>", " ", body)))
    return collapse_blank_lines(parser.text())


def collapse_blank_lines(text: str) -> str:
    """Убирает отступы-пустоту, которой в HTML всегда много."""
    lines = [line.rstrip() for line in unescape(text).splitlines()]
    out: list[str] = []
    blank = 0
    for line in lines:
        if line.strip():
            blank = 0
            out.append(line.strip() if not line.startswith(("    ", "\t")) else line)
        else:
            blank += 1
            if blank <= 1 and out:
                out.append("")
    return "\n".join(out).strip()


def raw_url(url: str) -> str:
    """Ссылка на сырой файл вместо страницы просмотра.

    Покрывает то, что реально вставляют из адресной строки: GitHub, GitLab и
    Bitbucket. Незнакомый адрес возвращается без изменений.
    """
    parts = urlsplit(url)
    host = parts.netloc.lower()
    path = parts.path

    if host in ("github.com", "www.github.com") and "/blob/" in path:
        return urlunsplit(
            ("https", "raw.githubusercontent.com", path.replace("/blob/", "/", 1), "", "")
        )
    if host.endswith("gitlab.com") and "/-/blob/" in path:
        return urlunsplit((parts.scheme, parts.netloc, path.replace("/-/blob/", "/-/raw/", 1), "", ""))
    if host in ("bitbucket.org", "www.bitbucket.org") and "/src/" in path:
        return urlunsplit((parts.scheme, parts.netloc, path.replace("/src/", "/raw/", 1), "", ""))
    return url


def clean_snapshot(body: str, content_type: str = "", limit: int | None = None) -> str:
    """Готовый к показу текст лицензии."""
    text = html_to_text(body) if looks_like_html(body, content_type) else collapse_blank_lines(body)
    if limit is not None:
        text = text[:limit]
    return text
