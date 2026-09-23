// Package crypto — шифрование чувствительных данных: refresh-токенов GitLab.
// Порт backend/app/core/crypto.py.
//
// Формат — Fernet (spec.md проекта fernet), и это НЕ произвольный выбор.
// Токены, зашифрованные python-версией, лежат в базе прямо сейчас, и
// go-версия обязана их читать: иначе все, кто подключил GitLab, обнаружат,
// что подключение «слетело», — без единой ошибки в логах, просто перестанет
// работать чтение файла из приватного проекта.
//
// Устройство формата, на stdlib и без зависимостей:
//
//	ключ   — base64url(32 байта) = 16 байт для HMAC + 16 для AES
//	токен  — base64url(версия || время || IV || шифртекст || HMAC)
//	         0x80 | 8 байт big-endian unix | 16 байт IV | N байт | 32 байта
//	шифр   — AES-128-CBC с набивкой PKCS#7
//	подпись — HMAC-SHA256 по всему, что до неё
//
// Проверка подписи идёт ДО расшифровки и в постоянное время: иначе
// подобранный шифртекст расшифровывался бы в мусор, а разница во времени
// ответа рассказывала бы о ключе.
package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"time"
)

// ErrNotConfigured — ключ не задан. Отдельная ошибка: «шифровать нечем» —
// это ошибка развёртывания, а не сломанный токен, и чинят их по-разному.
var ErrNotConfigured = errors.New("не задан FERNET_KEY — шифрование токенов GitLab невозможно")

// ErrInvalidToken — токен не расшифровался. Чаще всего это значит, что
// FERNET_KEY сменили: прежние токены становятся нечитаемыми, и пользователям
// надо подключить GitLab заново.
var ErrInvalidToken = errors.New("токен не расшифрован: возможно, FERNET_KEY изменён")

const (
	versionByte  = 0x80
	timestampLen = 8
	ivLen        = aes.BlockSize
	hmacLen      = sha256.Size
	// minTokenLen — версия + время + IV + минимум один блок + подпись.
	minTokenLen = 1 + timestampLen + ivLen + aes.BlockSize + hmacLen
)

// Fernet — ключ шифрования.
type Fernet struct {
	signingKey    []byte // первые 16 байт
	encryptionKey []byte // вторые 16 байт
	// now подменяется в тестах.
	now func() time.Time
}

// New разбирает ключ из настройки.
//
// Пустой ключ — не ошибка сборки: сервис поднимается и без GitLab, и падать
// из-за неиспользуемой интеграции нельзя. nil-получатель методов отвечает
// ErrNotConfigured, то есть проблема всплывает там, где ею пользуются.
func New(key string) (*Fernet, error) {
	if key == "" {
		return nil, ErrNotConfigured
	}
	raw, err := base64.URLEncoding.DecodeString(key)
	if err != nil {
		// Ключ генерируют командой из документации, и самая частая ошибка —
		// потерянный при копировании символ. Сказать об этом прямо дешевле,
		// чем «неверный формат».
		return nil, fmt.Errorf(
			"FERNET_KEY не разобран как base64: %w. Сгенерировать: "+
				`python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"`,
			err)
	}
	if len(raw) != 32 {
		return nil, fmt.Errorf(
			"FERNET_KEY имеет длину %d байт после раскодирования, а нужно 32 "+
				"(16 для подписи и 16 для шифрования)", len(raw))
	}
	return &Fernet{signingKey: raw[:16], encryptionKey: raw[16:]}, nil
}

func (f *Fernet) clock() time.Time {
	if f != nil && f.now != nil {
		return f.now()
	}
	return time.Now()
}

// Encrypt шифрует значение.
func (f *Fernet) Encrypt(value string) (string, error) {
	if f == nil {
		return "", ErrNotConfigured
	}
	block, err := aes.NewCipher(f.encryptionKey)
	if err != nil {
		return "", err
	}

	iv := make([]byte, ivLen)
	if _, err := rand.Read(iv); err != nil {
		return "", fmt.Errorf("генерация вектора инициализации: %w", err)
	}

	padded := padPKCS7([]byte(value), aes.BlockSize)
	ciphertext := make([]byte, len(padded))
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(ciphertext, padded)

	body := make([]byte, 0, 1+timestampLen+ivLen+len(ciphertext)+hmacLen)
	body = append(body, versionByte)
	body = binary.BigEndian.AppendUint64(body, uint64(f.clock().Unix())) //nolint:gosec // время не отрицательное
	body = append(body, iv...)
	body = append(body, ciphertext...)

	mac := hmac.New(sha256.New, f.signingKey)
	mac.Write(body)
	body = mac.Sum(body)

	return base64.URLEncoding.EncodeToString(body), nil
}

// Decrypt расшифровывает значение.
//
// Срок жизни токена (ttl из спецификации Fernet) намеренно не проверяется:
// python-версия его тоже не проверяет, а refresh-токен GitLab живёт до
// отзыва. Проверка привела бы к тому, что подключение «слетает» само по
// себе через сутки.
func (f *Fernet) Decrypt(token string) (string, error) {
	if f == nil {
		return "", ErrNotConfigured
	}
	body, err := base64.URLEncoding.DecodeString(token)
	if err != nil {
		return "", fmt.Errorf("%w: значение не разобрано как base64", ErrInvalidToken)
	}
	if len(body) < minTokenLen {
		return "", fmt.Errorf("%w: длина %d байт меньше минимальной", ErrInvalidToken, len(body))
	}
	if body[0] != versionByte {
		return "", fmt.Errorf("%w: неизвестная версия формата 0x%x", ErrInvalidToken, body[0])
	}

	signed, signature := body[:len(body)-hmacLen], body[len(body)-hmacLen:]
	mac := hmac.New(sha256.New, f.signingKey)
	mac.Write(signed)
	// Сравнение в постоянное время: разница во времени ответа на подобранный
	// шифртекст рассказывала бы о ключе.
	if subtle.ConstantTimeCompare(mac.Sum(nil), signature) != 1 {
		return "", fmt.Errorf("%w: подпись не совпала", ErrInvalidToken)
	}

	iv := signed[1+timestampLen : 1+timestampLen+ivLen]
	ciphertext := signed[1+timestampLen+ivLen:]
	if len(ciphertext) == 0 || len(ciphertext)%aes.BlockSize != 0 {
		return "", fmt.Errorf("%w: длина шифртекста не кратна размеру блока", ErrInvalidToken)
	}

	block, err := aes.NewCipher(f.encryptionKey)
	if err != nil {
		return "", err
	}
	plaintext := make([]byte, len(ciphertext))
	cipher.NewCBCDecrypter(block, iv).CryptBlocks(plaintext, ciphertext)

	unpadded, err := unpadPKCS7(plaintext, aes.BlockSize)
	if err != nil {
		// Подпись сошлась, а набивка — нет: это не подделка, а повреждение
		// данных в базе. Говорим прямо, иначе искать будут не там.
		return "", fmt.Errorf("%w: %v", ErrInvalidToken, err)
	}
	return string(unpadded), nil
}

// padPKCS7 добавляет набивку. Полный блок добавляется и тогда, когда длина уже
// кратна размеру блока: иначе снять набивку однозначно нельзя.
func padPKCS7(data []byte, blockSize int) []byte {
	n := blockSize - len(data)%blockSize
	out := make([]byte, len(data), len(data)+n)
	copy(out, data)
	for i := 0; i < n; i++ {
		out = append(out, byte(n))
	}
	return out
}

func unpadPKCS7(data []byte, blockSize int) ([]byte, error) {
	if len(data) == 0 || len(data)%blockSize != 0 {
		return nil, errors.New("длина данных не кратна размеру блока")
	}
	n := int(data[len(data)-1])
	if n == 0 || n > blockSize || n > len(data) {
		return nil, errors.New("неверная длина набивки")
	}
	// Проверяем ВСЕ байты набивки, а не только последний: иначе повреждённые
	// данные иногда проходили бы как валидные.
	for _, b := range data[len(data)-n:] {
		if int(b) != n {
			return nil, errors.New("набивка повреждена")
		}
	}
	return data[:len(data)-n], nil
}
