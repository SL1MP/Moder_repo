package policy

import (
	"sync/atomic"
	"time"
)

// Перезагрузка политик без перезапуска сервиса.
//
// Закрывает долг, отмеченный в status.md: в python-версии есть POST
// /admin/reload, в go-версии правка config/blacklist.yml требовала рестарта.
// Разница не косметическая — перезапуск api-go рвёт открытые запросы, а
// blacklist правят как раз в тот момент, когда надо срочно запретить пакет.
//
// Держатель, а не глобальная переменная с мьютексом: читают политику на каждом
// пакете и на каждом запросе списка лицензий, пишут — раз в неделю. atomic
// указатель делает чтение бесплатным, а подмену — атомарной, без окна, в
// котором виден полузагруженный справочник.
//
// Важно: подменяется указатель целиком, а не содержимое. Правка загруженной
// структуры на месте означала бы, что шаг конвейера, читающий её прямо сейчас,
// увидит половину старых правил и половину новых.

// Holder — текущая пара политик и то, как их перечитать.
type Holder struct {
	blacklistPath string
	licensesPath  string

	blacklist atomic.Pointer[Blacklist]
	licenses  atomic.Pointer[LicensePolicy]

	// reloadedAt — когда политики последний раз перечитывали. Показывается на
	// экране «Настройка»: «правила загружены» без времени не отвечает на
	// вопрос, подхватил ли сервис вчерашнюю правку.
	reloadedAt atomic.Int64
}

// NewHolder читает файлы и запоминает пути для последующих перезагрузок.
//
// Ошибки чтения не возвращаются: непрочитанный файл не роняет сервис, но и не
// выдаёт себя за пустой список — это видно через Failed() у самой политики.
// Тот же принцип, что у LoadBlacklist и LoadLicensePolicy.
func NewHolder(blacklistPath, licensesPath string) *Holder {
	h := &Holder{blacklistPath: blacklistPath, licensesPath: licensesPath}
	h.Reload()
	return h
}

// Blacklist — текущие правила запрета.
func (h *Holder) Blacklist() *Blacklist { return h.blacklist.Load() }

// Licenses — текущий справочник лицензий.
func (h *Holder) Licenses() *LicensePolicy { return h.licenses.Load() }

// ReloadedAt — когда политики последний раз перечитывали.
func (h *Holder) ReloadedAt() time.Time {
	return time.Unix(0, h.reloadedAt.Load()).UTC()
}

// ReloadResult — что получилось при перезагрузке.
//
// Ошибки полями, а не одной строкой: файла два, и сломанный blacklist при
// исправном справочнике лицензий — это другая ситуация, чем наоборот, и
// администратору надо знать, какой именно чинить.
type ReloadResult struct {
	BlacklistPath  string    `json:"blacklist_path"`
	BlacklistRules int       `json:"blacklist_rules"`
	BlacklistError string    `json:"blacklist_error,omitempty"`
	LicensesPath   string    `json:"licenses_path"`
	LicensesAllow  int       `json:"licenses_allowed"`
	LicensesForbid int       `json:"licenses_forbidden"`
	LicensesError  string    `json:"licenses_error,omitempty"`
	ReloadedAt     time.Time `json:"reloaded_at"`
}

// OK — оба файла прочитаны.
func (r ReloadResult) OK() bool { return r.BlacklistError == "" && r.LicensesError == "" }

// Reload перечитывает оба файла и подменяет их атомарно.
//
// Сломанный файл НЕ подменяет прежний: иначе опечатка в blacklist.yml
// мгновенно снимала бы все запреты — ровно в тот момент, когда его правят
// второпях, чтобы запретить пакет. Прежние правила остаются действовать, а
// ошибка возвращается вызывающему.
func (h *Holder) Reload() ReloadResult {
	now := time.Now().UTC()
	result := ReloadResult{
		BlacklistPath: h.blacklistPath, LicensesPath: h.licensesPath, ReloadedAt: now,
	}

	blacklist := LoadBlacklist(h.blacklistPath)
	if blacklist.Failed() {
		result.BlacklistError = blacklist.Err
		// Первая загрузка — особый случай: подменять нечего, и держать nil
		// нельзя. Кладём непрочитанную политику: она сама себя объявляет
		// сломанной, и шаг blacklist отдаст пакет DevSecOps вместо того,
		// чтобы пропустить его как «запрещать нечего».
		if h.blacklist.Load() == nil {
			h.blacklist.Store(blacklist)
		}
	} else {
		h.blacklist.Store(blacklist)
		result.BlacklistRules = len(blacklist.Rules)
	}

	licenses := LoadLicensePolicy(h.licensesPath)
	if licenses.Failed() {
		result.LicensesError = licenses.Err
		if h.licenses.Load() == nil {
			h.licenses.Store(licenses)
		}
	} else {
		h.licenses.Store(licenses)
		result.LicensesAllow = len(licenses.Allowed)
		result.LicensesForbid = len(licenses.Forbidden)
	}

	// Время обновляем в любом случае: вопрос «когда последний раз пытались
	// перечитать» не менее важен, чем «когда получилось».
	h.reloadedAt.Store(now.UnixNano())
	return result
}
