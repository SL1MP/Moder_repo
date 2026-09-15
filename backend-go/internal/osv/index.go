package osv

import (
	"context"
	"fmt"
	"math"
	"regexp"
	"strings"
	"time"
)

// Finding — уязвимость конкретной версии пакета.
type Finding struct {
	ExternalID     string   `json:"external_id"`
	Summary        string   `json:"summary,omitempty"`
	Aliases        []string `json:"aliases,omitempty"`
	CVSSVector     string   `json:"cvss_vector,omitempty"`
	CVSSScore      float64  `json:"cvss_score,omitempty"`
	Severity       string   `json:"severity,omitempty"`
	URL            string   `json:"url,omitempty"`
	FixedVersions  []string `json:"fixed_versions,omitempty"`
	AffectedRanges []any    `json:"affected_ranges,omitempty"`
}

// Score — нормализованный балл 0..100 (CVSS × 10). Порог vuln_max_score в
// конфигурации задан в этой же шкале, 1:1 с Python-версией.
func (f Finding) Score() float64 {
	return math.Round(f.CVSSScore*10*10) / 10
}

// IndexVersion — версия данных, по которой выносится решение.
type IndexVersion struct {
	Version     string
	Source      string
	Checksum    string
	PublishedAt *time.Time
	RemotePath  string
	LocalPath   string
	RecordCount int
}

// AgeDays — возраст снапшота в днях; nil, если дата публикации неизвестна.
func (v IndexVersion) AgeDays(now time.Time) *float64 {
	if v.PublishedAt == nil {
		return nil
	}
	age := now.Sub(*v.PublishedAt).Hours() / 24
	return &age
}

// Index — контракт источника данных об уязвимостях.
type Index interface {
	Source() string
	// CurrentVersion — версия данных, по которой будет вынесено решение.
	// nil означает «снапшот ни разу не загружался»: это не «уязвимостей нет»,
	// а повод отдать решение DevSecOps.
	CurrentVersion(ctx context.Context) (*IndexVersion, error)
	// Query — уязвимости конкретной версии пакета.
	Query(ctx context.Context, manager, name, version string) ([]Finding, error)
	// LocalDBPath — каталог с распакованной базой для offline-режима
	// osv-scanner; пусто, если такого каталога нет.
	LocalDBPath() string
}

// IsStale — устарел ли снапшот. Отсутствие снапшота считается устареванием:
// молча одобрять пакет на данных, которых нет, нельзя.
func IsStale(ctx context.Context, index Index, maxDays int, now time.Time) (bool, error) {
	info, err := index.CurrentVersion(ctx)
	if err != nil {
		return true, err
	}
	if info == nil {
		return true, nil
	}
	age := info.AgeDays(now)
	return age != nil && *age > float64(maxDays), nil
}

// --------------------------------------------------------------------------- CVSS

var cvssMetrics = map[string]map[string]float64{
	"AV":         {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2},
	"AC":         {"L": 0.77, "H": 0.44},
	"PR_none":    {"N": 0.85, "L": 0.62, "H": 0.27},
	"PR_changed": {"N": 0.85, "L": 0.68, "H": 0.5},
	"UI":         {"N": 0.85, "R": 0.62},
	"CIA":        {"H": 0.56, "L": 0.22, "N": 0.0},
}

// CVSSv3Score — базовый балл CVSS v3.x по вектору. Нужен, когда OSV отдаёт
// вектор без готового балла. Возвращает ok=false, если вектор неполон:
// балл 0 в этом случае означал бы «неопасно», что неверно.
func CVSSv3Score(vector string) (float64, bool) {
	if vector == "" || !strings.Contains(vector, "/") {
		return 0, false
	}
	parts := map[string]string{}
	for _, chunk := range strings.Split(strings.TrimSpace(vector), "/") {
		key, value, found := strings.Cut(chunk, ":")
		if !found || key == "CVSS" {
			continue
		}
		parts[key] = value
	}

	scopeChanged := parts["S"] == "C"
	prTable := "PR_none"
	if scopeChanged {
		prTable = "PR_changed"
	}
	lookup := func(table, key string) (float64, bool) {
		v, ok := cvssMetrics[table][parts[key]]
		return v, ok
	}
	av, ok1 := lookup("AV", "AV")
	ac, ok2 := lookup("AC", "AC")
	pr, ok3 := lookup(prTable, "PR")
	ui, ok4 := lookup("UI", "UI")
	conf, ok5 := lookup("CIA", "C")
	integ, ok6 := lookup("CIA", "I")
	avail, ok7 := lookup("CIA", "A")
	if !(ok1 && ok2 && ok3 && ok4 && ok5 && ok6 && ok7) {
		return 0, false
	}

	iss := 1 - (1-conf)*(1-integ)*(1-avail)
	var impact float64
	if scopeChanged {
		impact = 7.52*(iss-0.029) - 3.25*math.Pow(iss-0.02, 15)
	} else {
		impact = 6.42 * iss
	}
	if impact <= 0 {
		return 0, true
	}
	exploitability := 8.22 * av * ac * pr * ui
	raw := impact + exploitability
	if scopeChanged {
		raw *= 1.08
	}
	if raw > 10 {
		raw = 10
	}
	// round half up до одной десятой — как в спецификации CVSS.
	return math.Ceil(raw*10) / 10, true
}

// severityFallback — балл по текстовой оценке, когда вектора нет вовсе.
var severityFallback = map[string]float64{
	"CRITICAL": 9.0, "HIGH": 7.5, "MODERATE": 5.0, "MEDIUM": 5.0, "LOW": 3.0,
}

// --------------------------------------------------------------------------- записи OSV

// Record — запись OSV в объёме, который нужен для решения.
type Record struct {
	ID       string   `json:"id"`
	Summary  string   `json:"summary"`
	Details  string   `json:"details"`
	Aliases  []string `json:"aliases"`
	Affected []struct {
		Package struct {
			Ecosystem string `json:"ecosystem"`
			Name      string `json:"name"`
		} `json:"package"`
		Versions []string `json:"versions"`
		Ranges   []Range  `json:"ranges"`
	} `json:"affected"`
	Severity []struct {
		Type  string `json:"type"`
		Score string `json:"score"`
	} `json:"severity"`
	References []struct {
		Type string `json:"type"`
		URL  string `json:"url"`
	} `json:"references"`
	DatabaseSpecific struct {
		Severity string `json:"severity"`
	} `json:"database_specific"`
}

// Range — один `ranges[]`-элемент записи OSV.
type Range struct {
	Type   string              `json:"type"`
	Events []map[string]string `json:"events"`
}

// VersionMatchesRange — попадает ли версия в один диапазон.
//
// Диапазон задан цепочкой событий introduced/fixed/last_affected,
// отсортированной по возрастанию. Версия затронута, если после последнего
// применимого introduced не было fixed/last_affected, её отсекающего.
func VersionMatchesRange(manager, version string, r Range) bool {
	cmp := ComparatorFor(manager)
	affected := false
	for _, event := range r.Events {
		if intro, ok := event["introduced"]; ok {
			if intro == "0" || cmp(version, intro) >= 0 {
				affected = true
			}
			continue
		}
		if fixed, ok := event["fixed"]; ok {
			if cmp(version, fixed) >= 0 {
				affected = false
			}
			continue
		}
		if last, ok := event["last_affected"]; ok {
			if cmp(version, last) > 0 {
				affected = false
			}
		}
	}
	return affected
}

// FindingFromRecord строит находку из записи OSV, если версия попадает в
// затронутые диапазоны. ok=false — версия не затронута.
func FindingFromRecord(record Record, manager, version string) (Finding, bool) {
	ecosystem := strings.ToLower(Ecosystems[manager])
	cmp := ComparatorFor(manager)

	var matched []any
	fixedSet := map[string]struct{}{}

	for _, affected := range record.Affected {
		// Экосистема бывает с уточнением через двоеточие (Alpine:v3.16).
		entryEcosystem, _, _ := strings.Cut(affected.Package.Ecosystem, ":")
		if strings.ToLower(entryEcosystem) != ecosystem {
			continue
		}

		hit := false
		for _, explicit := range affected.Versions {
			if cmp(version, explicit) == 0 {
				hit = true
				break
			}
		}
		if !hit {
			for _, r := range affected.Ranges {
				// git-диапазоны не применимы к версиям реестра.
				if r.Type == "GIT" {
					continue
				}
				if VersionMatchesRange(manager, version, r) {
					hit = true
					break
				}
			}
		}
		if !hit {
			continue
		}
		matched = append(matched, map[string]any{
			"ranges": affected.Ranges, "versions": affected.Versions,
		})
		for _, r := range affected.Ranges {
			for _, event := range r.Events {
				if fixed, ok := event["fixed"]; ok && fixed != "" {
					fixedSet[fixed] = struct{}{}
				}
			}
		}
	}
	if len(matched) == 0 {
		return Finding{}, false
	}

	vector, score := "", 0.0
	for _, sev := range record.Severity {
		if strings.HasPrefix(sev.Type, "CVSS_V3") && sev.Score != "" {
			if parsed, ok := CVSSv3Score(sev.Score); ok {
				vector, score = sev.Score, parsed
			} else {
				vector = sev.Score
			}
			break
		}
	}
	if score == 0 {
		for _, sev := range record.Severity {
			if sev.Type == "CVSS_V4" && sev.Score != "" {
				vector = sev.Score
				break
			}
		}
	}
	label := strings.ToUpper(strings.TrimSpace(record.DatabaseSpecific.Severity))
	if score == 0 {
		if fallback, ok := severityFallback[label]; ok {
			score = fallback
		}
	}

	summary := record.Summary
	if summary == "" && record.Details != "" {
		summary = truncateRunes(record.Details, 500)
	}

	url := ""
	for _, ref := range record.References {
		if ref.Type == "ADVISORY" {
			url = ref.URL
			break
		}
	}
	if url == "" && record.ID != "" {
		url = "https://osv.dev/vulnerability/" + record.ID
	}

	return Finding{
		ExternalID:     record.ID,
		Summary:        summary,
		Aliases:        record.Aliases,
		CVSSVector:     vector,
		CVSSScore:      score,
		Severity:       label,
		URL:            url,
		FixedVersions:  sortedKeys(fixedSet),
		AffectedRanges: matched,
	}, true
}

func truncateRunes(s string, limit int) string {
	runes := []rune(s)
	if len(runes) <= limit {
		return s
	}
	return string(runes[:limit])
}

func sortedKeys(set map[string]struct{}) []string {
	if len(set) == 0 {
		return nil
	}
	out := make([]string, 0, len(set))
	for key := range set {
		out = append(out, key)
	}
	// Простая сортировка: версий-исправлений единицы.
	for i := 1; i < len(out); i++ {
		for j := i; j > 0 && out[j] < out[j-1]; j-- {
			out[j], out[j-1] = out[j-1], out[j]
		}
	}
	return out
}

var identifierRe = regexp.MustCompile(`^[A-Za-z0-9._\-]+$`)

// ValidIdentifier — проверка имени пакета перед подстановкой в путь снапшота:
// имя приходит из заявки и не должно уводить чтение за пределы каталога базы.
func ValidIdentifier(name string) bool {
	return identifierRe.MatchString(name)
}

// Summary — краткая сводка находок для сообщения шага: «GHSA-xxx (75), CVE-yyy (52)».
func Summary(findings []Finding) string {
	if len(findings) == 0 {
		return ""
	}
	parts := make([]string, 0, len(findings))
	for _, f := range findings {
		parts = append(parts, fmt.Sprintf("%s (%g)", f.ExternalID, f.Score()))
	}
	return strings.Join(parts, ", ")
}

// MaxScore — максимальный балл среди находок.
func MaxScore(findings []Finding) float64 {
	worst := 0.0
	for _, f := range findings {
		if score := f.Score(); score > worst {
			worst = score
		}
	}
	return worst
}
