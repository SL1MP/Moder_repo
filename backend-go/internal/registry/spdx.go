package registry

import (
	"regexp"
	"strings"
)

// Нормализация лицензий к SPDX-идентификаторам. Порт backend/app/services/spdx.py.
//
// Зачем это здесь, а не в отдельном пакете: единственный потребитель —
// разбор метаданных реестра. Справочник разрешённых лицензий (licenses.yml) —
// другая сущность и живёт в политиках конвейера.

// spdxAliases — частые написания в метаданных реестров -> канонический
// SPDX-идентификатор.
var spdxAliases = map[string]string{
	"mit":                         "MIT",
	"mit license":                 "MIT",
	"the mit license":             "MIT",
	"apache 2.0":                  "Apache-2.0",
	"apache-2.0":                  "Apache-2.0",
	"apache license 2.0":          "Apache-2.0",
	"apache software license":     "Apache-2.0",
	"apache license, version 2.0": "Apache-2.0",
	"bsd":                         "BSD-3-Clause",
	"bsd license":                 "BSD-3-Clause",
	"bsd-3-clause":                "BSD-3-Clause",
	"new bsd license":             "BSD-3-Clause",
	"bsd 3-clause":                "BSD-3-Clause",
	"bsd-2-clause":                "BSD-2-Clause",
	"simplified bsd":              "BSD-2-Clause",
	"isc":                         "ISC",
	"isc license":                 "ISC",
	"mpl-2.0":                     "MPL-2.0",
	"mozilla public license 2.0":  "MPL-2.0",
	"gpl-2.0":                     "GPL-2.0-only",
	"gplv2":                       "GPL-2.0-only",
	"gpl-3.0":                     "GPL-3.0-only",
	"gplv3":                       "GPL-3.0-only",
	"lgpl-2.1":                    "LGPL-2.1-only",
	"lgpl-3.0":                    "LGPL-3.0-only",
	"agpl-3.0":                    "AGPL-3.0-only",
	"unlicense":                   "Unlicense",
	"the unlicense":               "Unlicense",
	"cc0-1.0":                     "CC0-1.0",
	"python-2.0":                  "Python-2.0",
	"psf":                         "Python-2.0",
	"psf-2.0":                     "Python-2.0",
	"zlib":                        "Zlib",
	"artistic-2.0":                "Artistic-2.0",
	"ms-pl":                       "MS-PL",
	"proprietary":                 "LicenseRef-Proprietary",
}

// spdxUnknown — написания, означающие «лицензия не указана». Их нельзя
// пропускать как идентификатор: «unknown» в поле SPDX прошло бы сверку со
// справочником как обычное имя лицензии и молча уехало бы мимо юриста.
var spdxUnknown = map[string]bool{
	"unknown": true, "none": true, "unlicensed": true,
	"see license": true, "other/proprietary license": true,
}

var (
	spdxIDRe        = regexp.MustCompile(`^[A-Za-z0-9.+\-]+$`)
	spdxOperatorRe  = regexp.MustCompile(`(?i)\b(or|and|with)\b`)
	classifierRe    = regexp.MustCompile(`^License :: (?:OSI Approved :: )?(.+)$`)
	whitespaceRunRe = regexp.MustCompile(`\s+`)
)

var classifierMap = map[string]string{
	"mit license":                                   "MIT",
	"apache software license":                       "Apache-2.0",
	"bsd license":                                   "BSD-3-Clause",
	"isc license (iscl)":                            "ISC",
	"mozilla public license 2.0 (mpl 2.0)":          "MPL-2.0",
	"gnu general public license v2 (gplv2)":         "GPL-2.0-only",
	"gnu general public license v3 (gplv3)":         "GPL-3.0-only",
	"gnu lesser general public license v2 (lgplv2)": "LGPL-2.1-only",
	"gnu lesser general public license v3 (lgplv3)": "LGPL-3.0-only",
	"gnu affero general public license v3":          "AGPL-3.0-only",
	"python software foundation license":            "Python-2.0",
	"the unlicense (unlicense)":                     "Unlicense",
	"zope public license":                           "ZPL-2.1",
}

// NormalizeSPDX приводит строку лицензии к SPDX-идентификатору. Пустая строка —
// не определилась; тогда решение принимает юрист (шаг 3 конвейера).
func NormalizeSPDX(value string) string {
	text := strings.TrimSpace(whitespaceRunRe.ReplaceAllString(strings.TrimSpace(value), " "))
	// Длинный текст вместо идентификатора: некоторые пакеты кладут в поле
	// license всю лицензию целиком.
	if text == "" || len(text) > 200 {
		return ""
	}
	lowered := strings.ToLower(text)
	if spdxUnknown[lowered] {
		return ""
	}
	if canonical, ok := spdxAliases[lowered]; ok {
		return canonical
	}
	// Составные выражения (`MIT OR Apache-2.0`) оставляем как есть: решение по
	// ним всё равно принимает юрист.
	if spdxOperatorRe.MatchString(lowered) && looksLikeExpression(text) {
		return text
	}
	if spdxIDRe.MatchString(text) {
		return text
	}
	return ""
}

func looksLikeExpression(text string) bool {
	tokens := strings.Fields(text)
	meaningful := 0
	for _, token := range tokens {
		switch strings.ToUpper(token) {
		case "OR", "AND", "WITH":
			continue
		}
		meaningful++
		if !spdxIDRe.MatchString(strings.Trim(token, "()")) {
			return false
		}
	}
	return meaningful > 0
}

// SPDXFromClassifiers достаёт лицензию из classifiers PyPI, если поле license
// пустое.
func SPDXFromClassifiers(classifiers []string) string {
	for _, classifier := range classifiers {
		match := classifierRe.FindStringSubmatch(strings.TrimSpace(classifier))
		if match == nil {
			continue
		}
		name := strings.TrimSpace(match[1])
		if mapped, ok := classifierMap[strings.ToLower(name)]; ok {
			return mapped
		}
		if direct := NormalizeSPDX(name); direct != "" {
			return direct
		}
	}
	return ""
}
