package crypto_test

import (
	_ "embed"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"moderation/internal/crypto"
)

// vectorsJSON — пары «открытый текст / токен», СГЕНЕРИРОВАННЫЕ БИБЛИОТЕКОЙ
// PYTHON (cryptography.fernet), а не этой реализацией.
//
// В этом весь смысл проверки. Свои тесты «зашифровали — расшифровали» ловят
// только несогласованность с самой собой: реализация, перепутавшая порядок
// полей или ключей, пройдёт их все. А токены python-версии лежат в базе прямо
// сейчас, и go-версия обязана их читать — иначе все, кто подключил GitLab,
// обнаружат, что подключение «слетело», без единой ошибки в логах.
//
//go:embed testdata_vectors.json
var vectorsJSON []byte

type vectors struct {
	Key   string `json:"key"`
	Pairs []struct {
		Plain string `json:"plain"`
		Token string `json:"token"`
	} `json:"pairs"`
}

func loadVectors(t *testing.T) vectors {
	t.Helper()
	var v vectors
	if err := json.Unmarshal(vectorsJSON, &v); err != nil {
		t.Fatalf("контрольные значения не разобраны: %v", err)
	}
	if len(v.Pairs) == 0 {
		t.Fatal("контрольных значений нет")
	}
	return v
}

// TestDecryptsPythonTokens — то, ради чего формат и выбран.
func TestDecryptsPythonTokens(t *testing.T) {
	v := loadVectors(t)
	f, err := crypto.New(v.Key)
	if err != nil {
		t.Fatalf("ключ не принят: %v", err)
	}
	for _, pair := range v.Pairs {
		got, err := f.Decrypt(pair.Token)
		if err != nil {
			t.Errorf("токен python-версии не расшифрован (%q): %v", pair.Plain, err)
			continue
		}
		if got != pair.Plain {
			t.Errorf("расшифровано %q, ожидалось %q", got, pair.Plain)
		}
	}
}

// TestRoundTrip — своё шифрование читается своим же расшифрованием.
func TestRoundTrip(t *testing.T) {
	v := loadVectors(t)
	f, err := crypto.New(v.Key)
	if err != nil {
		t.Fatal(err)
	}
	for _, plain := range []string{"", "короткий", strings.Repeat("длинный ", 500)} {
		token, err := f.Encrypt(plain)
		if err != nil {
			t.Fatalf("шифрование: %v", err)
		}
		got, err := f.Decrypt(token)
		if err != nil {
			t.Fatalf("расшифрование: %v", err)
		}
		if got != plain {
			t.Errorf("получено %q, ожидалось %q", got, plain)
		}
	}
}

// TestTamperedTokenIsRejected — подделанный токен не расшифровывается.
//
// Проверка подписи идёт ДО расшифровки: иначе подобранный шифртекст
// расшифровывался бы в мусор, и по этому мусору можно было бы подбирать ключ.
func TestTamperedTokenIsRejected(t *testing.T) {
	v := loadVectors(t)
	f, err := crypto.New(v.Key)
	if err != nil {
		t.Fatal(err)
	}
	token, err := f.Encrypt("glpat-секрет")
	if err != nil {
		t.Fatal(err)
	}

	// Портим один символ в середине — это и шифртекст, и подпись под ним.
	broken := []byte(token)
	mid := len(broken) / 2
	if broken[mid] == 'A' {
		broken[mid] = 'B'
	} else {
		broken[mid] = 'A'
	}
	if _, err := f.Decrypt(string(broken)); !errors.Is(err, crypto.ErrInvalidToken) {
		t.Errorf("подделанный токен принят (ошибка: %v)", err)
	}
}

// TestWrongKeyIsRejected — смена FERNET_KEY делает прежние токены
// нечитаемыми, и это должно быть видно, а не превращаться в мусор.
func TestWrongKeyIsRejected(t *testing.T) {
	v := loadVectors(t)
	other, err := crypto.New("bm90LXRoZS1zYW1lLWtleS0zMi1ieXRlcy1sb25nISE=")
	if err != nil {
		t.Fatalf("тестовый ключ не принят: %v", err)
	}
	if _, err := other.Decrypt(v.Pairs[0].Token); !errors.Is(err, crypto.ErrInvalidToken) {
		t.Errorf("токен расшифрован чужим ключом (ошибка: %v)", err)
	}
}

// TestBadKeysAreExplained — ошибка в ключе называет себя.
//
// Ключ копируют из вывода команды, и самая частая беда — потерянный символ.
// «неверный формат» оставляет гадать, а сообщение с длиной — нет.
func TestBadKeysAreExplained(t *testing.T) {
	if _, err := crypto.New(""); !errors.Is(err, crypto.ErrNotConfigured) {
		t.Errorf("пустой ключ: %v", err)
	}
	if _, err := crypto.New("не base64!!!"); err == nil {
		t.Error("ключ не в base64 принят")
	}
	// Правильный base64, но 16 байт вместо 32.
	if _, err := crypto.New("MTIzNDU2Nzg5MDEyMzQ1Ng=="); err == nil {
		t.Error("ключ неверной длины принят")
	} else if !strings.Contains(err.Error(), "32") {
		t.Errorf("ошибка не называет нужную длину: %v", err)
	}
}

// TestNilFernetIsNotConfigured — сервис поднимается и без GitLab, и падать
// из-за неиспользуемой интеграции нельзя: проблема всплывает там, где ею
// пользуются.
func TestNilFernetIsNotConfigured(t *testing.T) {
	var f *crypto.Fernet
	if _, err := f.Encrypt("x"); !errors.Is(err, crypto.ErrNotConfigured) {
		t.Errorf("шифрование без ключа: %v", err)
	}
	if _, err := f.Decrypt("x"); !errors.Is(err, crypto.ErrNotConfigured) {
		t.Errorf("расшифрование без ключа: %v", err)
	}
}
