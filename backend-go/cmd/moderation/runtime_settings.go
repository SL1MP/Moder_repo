package main

import (
	"context"
	"log/slog"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"moderation/internal/config"
	"moderation/internal/repo"
)

const (
	settingsListenRetry          = 2 * time.Second
	settingsListenStartupTimeout = 5 * time.Second
	settingsRestartGrace         = time.Second
)

// applyStoredSettings накладывает web-настройки поверх .env до создания
// клиентов реестров, артефактори и конвейера. Если миграция ещё не применена,
// процесс продолжает запуск с .env — migrate-go стартует отдельно и первым.
func applyStoredSettings(
	ctx context.Context, pool *pgxpool.Pool, cfg *config.Config, logger *slog.Logger,
) {
	values, err := repo.New(pool).AppSettings(ctx)
	if err != nil {
		logger.Warn("web-настройки не загружены, используются значения .env", "error", err)
		return
	}
	if len(values) == 0 {
		return
	}
	if err := cfg.ApplyOverrides(values); err != nil {
		logger.Error("сохранённые web-настройки невалидны, используются значения .env", "error", err)
		return
	}
	logger.Info("применены web-настройки", "количество", len(values))
}

// watchStoredSettings ждёт транзакционное уведомление от SaveAppSettings.
// Клиенты Nexus, реестров, sandbox и OSV собраны вокруг Config при запуске,
// поэтому частичная мутация Config на лету была бы опасна: разные части одного
// прогона использовали бы разные адреса. Процессы вместо этого корректно
// завершаются и поднимаются политикой restart оркестратора уже с целостным
// новым набором настроек.
func watchStoredSettings(
	ctx context.Context, pool *pgxpool.Pool, logger *slog.Logger,
) <-chan struct{} {
	changed := make(chan struct{}, 1)
	ready := make(chan struct{})
	go func() {
		announcedReady := false
		for ctx.Err() == nil {
			conn, err := pool.Acquire(ctx)
			if err == nil {
				// Соединение могло раньше использоваться Queue.Wait и сохранить
				// session-level LISTEN. Иначе обычная задача конвейера могла бы
				// ошибочно выглядеть как изменение настроек.
				_, err = conn.Exec(ctx, "UNLISTEN *")
			}
			if err == nil {
				_, err = conn.Exec(ctx, "LISTEN "+repo.AppSettingsChannel)
			}
			if err == nil {
				if !announcedReady {
					close(ready)
					announcedReady = true
				}
				for err == nil {
					var notificationChannel string
					notification, waitErr := conn.Conn().WaitForNotification(ctx)
					err = waitErr
					if notification != nil {
						notificationChannel = notification.Channel
					}
					if err == nil && notificationChannel == repo.AppSettingsChannel {
						// Несколько быстрых сохранений объединяем: получатель всегда
						// перечитывает весь набор значений из БД, поэтому достаточно
						// одного ожидающего события.
						select {
						case changed <- struct{}{}:
						default:
						}
					}
				}
			}
			if conn != nil {
				conn.Release()
			}
			if ctx.Err() != nil {
				return
			}
			logger.Warn("подписка на изменения web-настроек прервана, повторяю", "error", err)
			timer := time.NewTimer(settingsListenRetry)
			select {
			case <-ctx.Done():
				timer.Stop()
				return
			case <-timer.C:
			}
		}
	}()

	timer := time.NewTimer(settingsListenStartupTimeout)
	defer timer.Stop()
	select {
	case <-ready:
	case <-ctx.Done():
	case <-timer.C:
		logger.Warn("подписка на изменения web-настроек не готова при запуске; повтор продолжается в фоне")
	}
	return changed
}

// restartOnStoredSettingsChange даёт HTTP-обработчику сохранения секунду
// вернуть ответ браузеру, затем отменяет общий контекст процесса. Дальше
// срабатывает обычное graceful shutdown, а Docker/оркестратор с restart policy
// запускает процесс заново.
func restartOnStoredSettingsChange(
	ctx context.Context, changed <-chan struct{}, stop context.CancelFunc, logger *slog.Logger,
) {
	go func() {
		select {
		case <-ctx.Done():
			return
		case <-changed:
			logger.Info("web-настройки изменены, запланирован автоматический перезапуск")
		}

		timer := time.NewTimer(settingsRestartGrace)
		defer timer.Stop()
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
			stop()
		}
	}()
}
