// Package licensesnap — снапшот текста лицензии по ссылке, приложенной
// разработчиком. Порт backend/app/services/license_snapshot.py.
//
// Юрист смотрит на этот текст, принимая решение, поэтому важно, чтобы он был
// читаемым. Ссылку обычно берут из адресной строки браузера — а это страница
// просмотра файла в репозитории (github.com/owner/repo/blob/main/LICENSE),
// которая отдаёт целый HTML-документ. Раньше он сохранялся как есть, и в
// карточке вместо текста лицензии показывалась разметка вперемешку со
// скриптами.
//
// Отсюда две вещи: ссылка на страницу просмотра переводится в ссылку на сырой
// файл, а если ответ всё равно оказался HTML — из него вынимается текст.
package licensesnap

import (
	"html"
	"net/url"
	"regexp"
	"strings"
)

// skipContent — теги, содержимое которых в текст лицензии попадать не должно.
var skipContent = map[string]bool{
	"script": true, "style": true, "noscript": true,
	"template": true, "svg": true, "head": true,
}

// breakAfter — теги, на которых имеет смысл переносить строку.
var breakAfter = map[string]bool{
	"p": true, "br": true, "div": true, "li": true, "tr": true,
	"h1": true, "h2": true, "h3": true, "h4": true, "h5": true, "h6": true,
	"pre": true, "article": true,
}

// RawURL — ссылка на сырой файл вместо страницы просмотра.
//
// Покрывает то, что реально вставляют из адресной строки: GitHub, GitLab и
// Bitbucket. Незнакомый адрес возвращается без изменений — догадываться о
// раскладке чужого хостинга не по чему, а испорченная ссылка хуже исходной.
func RawURL(raw string) string {
	parsed, err := url.Parse(raw)
	if err != nil {
		return raw
	}
	host := strings.ToLower(parsed.Host)
	path := parsed.Path

	switch {
	case (host == "github.com" || host == "www.github.com") && strings.Contains(path, "/blob/"):
		return (&url.URL{
			Scheme: "https", Host: "raw.githubusercontent.com",
			Path: strings.Replace(path, "/blob/", "/", 1),
		}).String()
	case strings.HasSuffix(host, "gitlab.com") && strings.Contains(path, "/-/blob/"):
		return (&url.URL{
			Scheme: parsed.Scheme, Host: parsed.Host,
			Path: strings.Replace(path, "/-/blob/", "/-/raw/", 1),
		}).String()
	case (host == "bitbucket.org" || host == "www.bitbucket.org") && strings.Contains(path, "/src/"):
		return (&url.URL{
			Scheme: parsed.Scheme, Host: parsed.Host,
			Path: strings.Replace(path, "/src/", "/raw/", 1),
		}).String()
	}
	return raw
}

// LooksLikeHTML — похож ли ответ на HTML-страницу.
func LooksLikeHTML(body, contentType string) bool {
	if strings.Contains(strings.ToLower(contentType), "html") {
		return true
	}
	head := strings.ToLower(strings.TrimSpace(body))
	if len(head) > 400 {
		head = head[:400]
	}
	return strings.HasPrefix(head, "<!doctype html") ||
		strings.HasPrefix(head, "<html") ||
		strings.Contains(head, "<body")
}

// HTMLToText вынимает видимый текст из разметки.
//
// Разбор написан на stdlib, без golang.org/x/net/html. Задача простая — снять
// теги и не взять содержимое script/style, — а зависимость ради неё тянет в
// сборку весь пакет разбора HTML. Тот же принцип, по которому в проекте нет
// aws-sdk ради четырёх операций с хранилищем.
//
// Разбор намеренно нестрогий: битая разметка не должна давать пустой снапшот,
// потому что пустой снапшот означает, что юрист не увидит ничего.
func HTMLToText(body string) string {
	var out strings.Builder
	out.Grow(len(body) / 2)

	// skip — во сколько незакрытых тегов из skipContent мы вошли.
	skip := 0
	for i := 0; i < len(body); {
		open := strings.IndexByte(body[i:], '<')
		if open < 0 {
			if skip == 0 {
				out.WriteString(body[i:])
			}
			break
		}
		if skip == 0 {
			out.WriteString(body[i : i+open])
		}
		i += open

		close := strings.IndexByte(body[i:], '>')
		if close < 0 {
			// Незакрытый тег до конца документа: остаток — не текст, и
			// показывать его как текст лицензии нельзя.
			break
		}
		tag := body[i+1 : i+close]
		i += close + 1

		name, closing := tagName(tag)
		switch {
		case name == "":
			// Комментарий, doctype или мусор — пропускаем молча.
		case skipContent[name]:
			if closing {
				if skip > 0 {
					skip--
				}
			} else if !strings.HasSuffix(strings.TrimSpace(tag), "/") {
				skip++
			}
		case breakAfter[name] && skip == 0:
			out.WriteByte('\n')
		}
	}

	text := CollapseBlankLines(out.String())
	if strings.TrimSpace(text) == "" {
		return fallbackStrip(body)
	}
	return text
}

// tagName — имя тега в нижнем регистре и признак закрывающего.
//
// Пустое имя означает, что это не тег: комментарий, doctype или обломок
// разметки. Такое просто выбрасывается.
func tagName(tag string) (name string, closing bool) {
	tag = strings.TrimSpace(tag)
	if tag == "" || strings.HasPrefix(tag, "!") || strings.HasPrefix(tag, "?") {
		return "", false
	}
	if strings.HasPrefix(tag, "/") {
		closing, tag = true, strings.TrimSpace(tag[1:])
	}
	// Имя — до первого пробела или слеша самозакрывающегося тега.
	end := strings.IndexAny(tag, " \t\r\n/")
	if end >= 0 {
		tag = tag[:end]
	}
	tag = strings.ToLower(tag)
	for _, c := range tag {
		if !(c >= 'a' && c <= 'z') && !(c >= '0' && c <= '9') {
			return "", closing
		}
	}
	return tag, closing
}

var tagRe = regexp.MustCompile(`<[^>]+>`)

// fallbackStrip — запасной разбор, когда разметка не разобралась вовсе.
func fallbackStrip(body string) string {
	return CollapseBlankLines(html.UnescapeString(tagRe.ReplaceAllString(body, " ")))
}

// CollapseBlankLines убирает пустоту, которой в HTML всегда много.
//
// Одна пустая строка между абзацами остаётся: текст лицензии без разбиения на
// абзацы читается заметно хуже, а юристу его читать целиком.
func CollapseBlankLines(text string) string {
	lines := strings.Split(html.UnescapeString(text), "\n")
	out := make([]string, 0, len(lines))
	blank := 0
	for _, line := range lines {
		line = strings.TrimRight(line, " \t\r")
		if strings.TrimSpace(line) == "" {
			blank++
			if blank <= 1 && len(out) > 0 {
				out = append(out, "")
			}
			continue
		}
		blank = 0
		// Отступ в начале строки сохраняем: в лицензиях им размечены
		// перечисления, и срезав его, мы превратим список в сплошной текст.
		if strings.HasPrefix(line, "    ") || strings.HasPrefix(line, "\t") {
			out = append(out, line)
		} else {
			out = append(out, strings.TrimSpace(line))
		}
	}
	return strings.TrimSpace(strings.Join(out, "\n"))
}

// Clean — готовый к показу текст лицензии.
func Clean(body, contentType string, limit int) string {
	var text string
	if LooksLikeHTML(body, contentType) {
		text = HTMLToText(body)
	} else {
		text = CollapseBlankLines(body)
	}
	if limit > 0 && len(text) > limit {
		// Режем по рунам, а не по байтам: обрезанная посреди символа строка
		// невалидна в UTF-8 и в карточке показывается ромбиками.
		runes := []rune(text)
		if len(runes) > limit {
			text = string(runes[:limit])
		}
	}
	return text
}
