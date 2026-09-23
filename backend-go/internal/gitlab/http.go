package gitlab

import (
	"fmt"
	"io"
)

// readLimited читает не больше limit байт и отличает «ответ ровно по границе»
// от «ответ обрезан»: молча усечённый файл зависимостей разобрался бы
// наполовину, и заявка завелась бы на часть пакетов — без единой ошибки.
func readLimited(r io.Reader, limit int64) ([]byte, error) {
	data, err := io.ReadAll(io.LimitReader(r, limit+1))
	if err != nil {
		return nil, fmt.Errorf("чтение ответа GitLab: %w", err)
	}
	if int64(len(data)) > limit {
		return nil, fmt.Errorf("ответ GitLab больше допустимого предела (%d байт)", limit)
	}
	return data, nil
}
