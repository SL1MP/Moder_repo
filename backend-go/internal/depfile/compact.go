package depfile

import "strings"

// compactLines возвращает непустые строки сокращённого тестового формата.
// Комментариями считаются только строки, начинающиеся с # или //: символ #
// внутри conan reference является частью revision и удаляться не должен.
func compactLines(content []byte) []string {
	var lines []string
	for _, raw := range strings.Split(string(content), "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "//") {
			continue
		}
		lines = append(lines, line)
	}
	return lines
}
