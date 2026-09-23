package licensesnap_test

import (
	"strings"
	"testing"

	"moderation/internal/licensesnap"
)

// TestRawURLRewritesViewPages — ссылку берут из адресной строки браузера, а
// это страница просмотра. Без перевода на сырой файл в снапшот попадал бы
// HTML-документ целиком.
func TestRawURLRewritesViewPages(t *testing.T) {
	cases := map[string]string{
		"https://github.com/psf/requests/blob/main/LICENSE": "https://raw.githubusercontent.com/psf/requests/main/LICENSE",
		"https://gitlab.com/g/p/-/blob/master/LICENSE":      "https://gitlab.com/g/p/-/raw/master/LICENSE",
		"https://bitbucket.org/team/repo/src/main/LICENSE":  "https://bitbucket.org/team/repo/raw/main/LICENSE",
		// Незнакомый хостинг оставляем как есть: догадываться о чужой
		// раскладке не по чему, а испорченная ссылка хуже исходной.
		"https://example.com/LICENSE.txt": "https://example.com/LICENSE.txt",
		// Уже сырая ссылка GitHub не трогается.
		"https://raw.githubusercontent.com/psf/requests/main/LICENSE": "https://raw.githubusercontent.com/psf/requests/main/LICENSE",
	}
	for in, want := range cases {
		if got := licensesnap.RawURL(in); got != want {
			t.Errorf("RawURL(%q) = %q, ожидалось %q", in, got, want)
		}
	}
}

// TestHTMLToTextDropsScripts — содержимое script и style в текст лицензии
// попадать не должно.
//
// Ровно это и было поломкой: юрист видел разметку вперемешку со скриптами
// вместо текста лицензии.
func TestHTMLToTextDropsScripts(t *testing.T) {
	body := `<!doctype html><html><head><title>LICENSE</title>
		<style>.x{color:red}</style></head>
		<body><script>alert('привет')</script>
		<div>MIT License</div>
		<p>Permission is hereby granted, free of charge</p>
		</body></html>`

	text := licensesnap.Clean(body, "text/html", 0)
	if !strings.Contains(text, "MIT License") {
		t.Errorf("текст лицензии потерян: %q", text)
	}
	if !strings.Contains(text, "Permission is hereby granted") {
		t.Errorf("абзац лицензии потерян: %q", text)
	}
	for _, junk := range []string{"alert(", "color:red", "<div>", "doctype"} {
		if strings.Contains(text, junk) {
			t.Errorf("в тексте осталось %q: %q", junk, text)
		}
	}
	// Заголовок документа тоже внутри head — он не текст лицензии.
	if strings.Contains(text, "LICENSE</title>") {
		t.Errorf("содержимое head попало в текст: %q", text)
	}
}

// TestPlainTextIsKeptAsIs — сырой файл лицензии ничем не «улучшается».
func TestPlainTextIsKeptAsIs(t *testing.T) {
	body := "MIT License\n\nCopyright (c) 2024\n\n    Пункт с отступом\n"
	text := licensesnap.Clean(body, "text/plain", 0)
	if !strings.Contains(text, "MIT License") || !strings.Contains(text, "Copyright (c) 2024") {
		t.Errorf("текст изменён: %q", text)
	}
	// Отступ сохраняется: в лицензиях им размечены перечисления, и срезав его,
	// мы превратили бы список в сплошной текст.
	if !strings.Contains(text, "    Пункт с отступом") {
		t.Errorf("отступ потерян: %q", text)
	}
}

// TestBrokenMarkupStillYieldsText — битая разметка не даёт пустой снапшот.
//
// Пустой снапшот означает, что юрист не увидит ничего, и решение придётся
// принимать вслепую — хуже, чем неидеально разобранный текст.
func TestBrokenMarkupStillYieldsText(t *testing.T) {
	body := `<html><body><div>Apache License 2.0 <b>без закрытия`
	text := licensesnap.Clean(body, "text/html", 0)
	if !strings.Contains(text, "Apache License 2.0") {
		t.Errorf("на битой разметке потерян текст: %q", text)
	}
}

// TestCleanRespectsLimitByRunes — предел считается рунами, а не байтами.
//
// Обрезанная посреди символа строка невалидна в UTF-8 и показывается в
// карточке ромбиками.
func TestCleanRespectsLimitByRunes(t *testing.T) {
	body := strings.Repeat("лицензия ", 100)
	text := licensesnap.Clean(body, "text/plain", 50)
	if len([]rune(text)) > 50 {
		t.Errorf("длина = %d рун, предел 50", len([]rune(text)))
	}
	if !strings.HasPrefix(text, "лицензия") {
		t.Errorf("текст обрезан посреди символа: %q", text)
	}
}

// TestCollapseBlankLines — одна пустая строка между абзацами остаётся: без
// разбиения на абзацы текст лицензии читается заметно хуже.
func TestCollapseBlankLines(t *testing.T) {
	got := licensesnap.CollapseBlankLines("Первый\n\n\n\n\nВторой\n\n")
	if got != "Первый\n\nВторой" {
		t.Errorf("получено %q", got)
	}
}
