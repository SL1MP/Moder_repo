package sandbox

import (
	"crypto/tls"
	"io"
	"net/http"
)

// maxResponseBytes — потолок на ответ песочницы. Полный отчёт бывает крупным,
// но не безразмерным, а ответ целиком уходит в отчёт и в память воркера.
const maxResponseBytes = 8 << 20 // 8 МиБ

// readLimited читает не больше limit байт и отличает «ответ ровно по границе»
// от «ответ обрезан»: молча усечённый JSON разобрался бы с ошибкой разбора, и
// причину искали бы в песочнице, а не у себя.
func readLimited(r io.Reader, limit int64) ([]byte, error) {
	data, err := io.ReadAll(io.LimitReader(r, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, errTooLarge{limit: limit}
	}
	return data, nil
}

type errTooLarge struct{ limit int64 }

func (e errTooLarge) Error() string {
	return "ответ песочницы больше допустимого предела (" +
		byteSize(e.limit) + ") — проверьте SANDBOX_SHORT_RESULT"
}

func byteSize(n int64) string {
	const unit = 1 << 20
	if n >= unit {
		return itoa(n/unit) + " МиБ"
	}
	return itoa(n) + " Б"
}

func itoa(n int64) string {
	if n == 0 {
		return "0"
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	return string(buf[i:])
}

// insecureTransport — транспорт без проверки сертификата: эквивалент `curl -k`
// из CI-шаблона. Нужен, пока у песочницы самоподписанный сертификат; включается
// только явной настройкой SANDBOX_INSECURE_TLS.
func insecureTransport() http.RoundTripper {
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.TLSClientConfig = &tls.Config{InsecureSkipVerify: true} //nolint:gosec // см. комментарий
	return tr
}
