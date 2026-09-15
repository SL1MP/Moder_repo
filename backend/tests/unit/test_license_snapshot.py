"""Снапшот лицензии должен быть читаемым.

Ссылку берут из адресной строки браузера — это страница просмотра файла в
репозитории, отдающая HTML-документ целиком. Раньше он сохранялся как есть, и
юрист видел разметку и скрипты вместо текста лицензии.
"""

from __future__ import annotations

import pytest

from app.services.license_snapshot import (
    clean_snapshot,
    collapse_blank_lines,
    html_to_text,
    looks_like_html,
    raw_url,
)

GITHUB_PAGE = """<!DOCTYPE html><html><head><title>LICENSE</title>
<style>.hdr{color:red}</style><script>window.x=1;</script></head>
<body><div class="hdr">GitHub</div>
<article><pre>MIT License

Copyright (c) 2024 Example

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software &amp; associated documentation files.</pre></article>
<script>console.log('tracker')</script></body></html>"""


def test_scripts_and_styles_do_not_reach_the_lawyer():
    text = clean_snapshot(GITHUB_PAGE, "text/html")

    assert "window.x" not in text
    assert "console.log" not in text
    assert ".hdr{color:red}" not in text


def test_license_body_survives():
    text = clean_snapshot(GITHUB_PAGE, "text/html")

    assert "MIT License" in text
    assert "Copyright (c) 2024 Example" in text
    assert "Permission is hereby granted" in text


def test_html_entities_are_decoded():
    """&amp; в тексте лицензии должен читаться как «&»."""
    text = clean_snapshot(GITHUB_PAGE, "text/html")

    assert "software & associated" in text
    assert "&amp;" not in text


def test_plain_text_is_left_alone():
    body = "MIT License\n\nCopyright (c) 2024\n"
    assert clean_snapshot(body, "text/plain") == "MIT License\n\nCopyright (c) 2024"


def test_html_detected_without_content_type():
    """Сервер мог не прислать content-type — ориентируемся на само тело."""
    assert looks_like_html("<!doctype html><html><body>x</body></html>")
    assert not looks_like_html("MIT License\n\nCopyright")


def test_broken_markup_still_yields_text():
    """На битой разметке лучше отдать хоть что-то, чем упасть."""
    text = html_to_text("<p>MIT License<p>Copyright <b>2024")

    assert "MIT License" in text
    assert "Copyright" in text


def test_blank_lines_are_collapsed():
    assert collapse_blank_lines("a\n\n\n\n\nb") == "a\n\nb"


@pytest.mark.parametrize(
    ("given", "expected"),
    [
        (
            "https://github.com/psf/requests/blob/main/LICENSE",
            "https://raw.githubusercontent.com/psf/requests/main/LICENSE",
        ),
        (
            "https://gitlab.com/group/proj/-/blob/main/LICENSE",
            "https://gitlab.com/group/proj/-/raw/main/LICENSE",
        ),
        # Незнакомый адрес не трогаем.
        ("https://example.com/LICENSE.txt", "https://example.com/LICENSE.txt"),
        # Уже сырая ссылка тоже.
        (
            "https://raw.githubusercontent.com/psf/requests/main/LICENSE",
            "https://raw.githubusercontent.com/psf/requests/main/LICENSE",
        ),
    ],
)
def test_view_urls_are_rewritten_to_raw(given, expected):
    assert raw_url(given) == expected


def test_limit_is_applied():
    assert len(clean_snapshot("x" * 5000, "text/plain", limit=100)) == 100
