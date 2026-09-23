// Package queue — очередь конвейера поверх Postgres.
//
// Почему не брокер. Очередь здесь — это строки request_item в статусе
// `queued`; отдельного хранилища задач нет и не нужно:
//
//   - Задача и её состояние — одна и та же строка. У python-версии они
//     разъезжаются: задача живёт в Redis, состояние в Postgres, и потеря
//     сообщения оставляет пакет навсегда в «в очереди» (мина 8.1 старого
//     handoff). Здесь терять нечего — пока строка в `queued`, работа не
//     сделана, кто бы ни падал.
//   - Захват атомарен по построению: SELECT ... FOR UPDATE SKIP LOCKED плюс
//     UPDATE в одной транзакции. Два воркера не возьмут один пакет, и
//     доказательство этого — одна строка SQL, а не настройки брокера.
//   - Тот же захват делает python-версия (app/pipeline/claim.py), поэтому
//     go-воркер и python-воркер могут работать одновременно: ровно один из
//     них возьмёт пакет. Это и позволяет переносить воркер не «в один день».
//
// Мгновенность даёт LISTEN/NOTIFY: тот, кто ставит задачу, шлёт NOTIFY, а
// воркер ждёт на LISTEN. Опрос остаётся подстраховкой — уведомление можно
// пропустить (переподключение, рестарт), и единственная его потеря не должна
// означать зависший навсегда пакет.
//
// Пропускная способность у этой задачи — десятки-сотни пакетов в сутки, а не
// тысячи в секунду; при таких числах Postgres как очередь проще и надёжнее
// отдельного брокера, за который пришлось бы платить ещё одним сервисом в
// compose, ещё одним состоянием и ещё одним способом всё это рассинхронить.
package queue

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Channel — канал LISTEN/NOTIFY. Имя фиксировано: его знают и тот, кто ставит
// задачу, и тот, кто её ждёт.
const Channel = "moderation_pipeline"

// Job — захваченный пакет заявки.
type Job struct {
	ItemID int64
	// FromStep — с какого шага продолжать. Пустая строка — с начала.
	FromStep string
}

// Queue — очередь поверх пула подключений.
type Queue struct {
	pool *pgxpool.Pool
	// StaleAfter — сколько строка в статусе `running` может не обновляться,
	// прежде чем её признают брошенной упавшим процессом. Живой прогон
	// обновляет строку heartbeat'ом, поэтому отобрать работу у работающего
	// воркера нельзя.
	StaleAfter time.Duration
	now        func() time.Time
}

// New собирает очередь. staleAfter<=0 — шесть минут (у python-версии это
// PIPELINE_STUCK_AFTER_SECONDS × STALE_RUNNING_FACTOR = 120 × 3).
func New(pool *pgxpool.Pool, staleAfter time.Duration) *Queue {
	if staleAfter <= 0 {
		staleAfter = 6 * time.Minute
	}
	return &Queue{pool: pool, StaleAfter: staleAfter, now: time.Now}
}

// ErrEmpty — брать нечего. Отдельная ошибка, а не (nil, nil): «очередь пуста»
// — штатное состояние, и обрабатывать его молчаливым nil'ом значит однажды
// разыменовать его в вызывающем коде.
var ErrEmpty = errors.New("очередь пуста")

// ErrNotOurs — строка пакета больше не принадлежит этому прогону: статус
// сменили снаружи (автор закрыл заявку) или её перехватил другой воркер.
//
// Отдельная ошибка, а не тихое «ничего не сделал»: воркер обязан различать
// «повтор не назначен, потому что попытки кончились» и «повторять нечего,
// потому что пакет уже не наш». В первом случае пакет надо пометить неудачей,
// во втором — не трогать вовсе.
var ErrNotOurs = errors.New("пакет больше не принадлежит этому прогону")

// Claim забирает один пакет. Возвращает ErrEmpty, если работы нет.
//
// Эксклюзивность держится на двух вещах сразу, и обе нужны:
//
//   - FOR UPDATE SKIP LOCKED: второй воркер не ждёт на строке, которую уже
//     забрал первый, а сразу берёт следующую;
//   - повтор условия отбора в самом UPDATE: если два запроса всё же выбрали
//     одну строку, проигравший после снятия блокировки перечитает её и
//     увидит статус `running` со свежим updated_at — его UPDATE не затронет
//     ни одной строки, и он получит ErrEmpty.
//
// Проверено мутациями на живой базе: снятие любого ОДНОГО из двух условий
// эксклюзивность не ломает, снятие обоих сразу даёт один и тот же пакет двум
// и трём воркерам. Оставлены оба намеренно — они закрывают разные механизмы
// (блокировка строки и перепроверка условия после её снятия), и полагаться на
// то, что второй спасёт при потере первого, не хочется.
func (q *Queue) Claim(ctx context.Context) (Job, error) {
	staleBefore := q.now().UTC().Add(-q.StaleAfter)
	row := q.pool.QueryRow(ctx, `
		WITH candidate AS (
			SELECT id FROM request_item
			WHERE status = 'queued'
			   OR (status = 'running' AND updated_at < $1)
			ORDER BY id
			FOR UPDATE SKIP LOCKED
			LIMIT 1
		)
		UPDATE request_item ri
		SET status = 'running', updated_at = now()
		FROM candidate
		WHERE ri.id = candidate.id
		  AND (ri.status = 'queued' OR (ri.status = 'running' AND ri.updated_at < $1))
		RETURNING ri.id, ri.resume_from_step
	`, staleBefore)

	var job Job
	var fromStep *string
	if err := row.Scan(&job.ItemID, &fromStep); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return Job{}, ErrEmpty
		}
		return Job{}, fmt.Errorf("захват пакета из очереди: %w", err)
	}
	if fromStep != nil {
		job.FromStep = *fromStep
	}
	return job, nil
}

// ClaimStale забирает пакет, который ждёт дольше minAge.
//
// Нужен сторожу в процессе API: выделенный воркер, если он есть, забирает
// пакеты сразу, и сторож их не видит. Если выделенного воркера нет или он
// умер — пакет пролежит minAge и достанется сторожу. Так постановка в очередь
// не может кончиться тем, что работу не делает никто.
func (q *Queue) ClaimStale(ctx context.Context, minAge time.Duration) (Job, error) {
	if minAge <= 0 {
		return q.Claim(ctx)
	}
	now := q.now().UTC()
	queuedBefore := now.Add(-minAge)
	staleBefore := now.Add(-q.StaleAfter)
	row := q.pool.QueryRow(ctx, `
		WITH candidate AS (
			SELECT id FROM request_item
			WHERE (status = 'queued' AND updated_at < $1)
			   OR (status = 'running' AND updated_at < $2)
			ORDER BY id
			FOR UPDATE SKIP LOCKED
			LIMIT 1
		)
		UPDATE request_item ri
		SET status = 'running', updated_at = now()
		FROM candidate
		WHERE ri.id = candidate.id
		  AND ((ri.status = 'queued' AND ri.updated_at < $1)
		       OR (ri.status = 'running' AND ri.updated_at < $2))
		RETURNING ri.id, ri.resume_from_step
	`, queuedBefore, staleBefore)

	var job Job
	var fromStep *string
	if err := row.Scan(&job.ItemID, &fromStep); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return Job{}, ErrEmpty
		}
		return Job{}, fmt.Errorf("захват залежавшегося пакета: %w", err)
	}
	if fromStep != nil {
		job.FromStep = *fromStep
	}
	return job, nil
}

// Heartbeat отмечает, что прогон жив. Возвращает false, если строку уже
// перехватили: тогда прогон надо прекратить — иначе два процесса будут писать
// шаги одного пакета.
func (q *Queue) Heartbeat(ctx context.Context, itemID int64) (bool, error) {
	tag, err := q.pool.Exec(ctx,
		`UPDATE request_item SET updated_at = now() WHERE id = $1 AND status = 'running'`, itemID)
	if err != nil {
		return false, fmt.Errorf("отметка о жизни прогона #%d: %w", itemID, err)
	}
	return tag.RowsAffected() == 1, nil
}

// Enqueue ставит пакет в очередь и будит воркеров. fromStep — с какого шага
// продолжать, пустая строка — с начала.
//
// Статус ставится безусловно: постановка в очередь — это решение
// вызывающего (создали заявку, сняли блокировку), а не догадка по текущему
// состоянию строки.
func (q *Queue) Enqueue(ctx context.Context, itemID int64, fromStep string) error {
	var step any
	if fromStep != "" {
		step = fromStep
	}
	if _, err := q.pool.Exec(ctx, `
		UPDATE request_item
		SET status = 'queued', resume_from_step = $2, blocked_reason = NULL,
		    finished_at = NULL, updated_at = now()
		WHERE id = $1
	`, itemID, step); err != nil {
		return fmt.Errorf("постановка пакета #%d в очередь: %w", itemID, err)
	}
	return q.Notify(ctx)
}

// Notify будит ожидающих воркеров. Ошибка не фатальна для вызывающего:
// задача уже в базе, и её подберёт опрос — поэтому вызывающий волен её
// залогировать и идти дальше.
func (q *Queue) Notify(ctx context.Context) error {
	if _, err := q.pool.Exec(ctx, `SELECT pg_notify($1, '')`, Channel); err != nil {
		return fmt.Errorf("уведомление воркеров: %w", err)
	}
	return nil
}

// ClearResumeStep убирает отметку «продолжить с шага» после успешного прогона.
// Иначе следующий запуск того же пакета молча начался бы с середины.
func (q *Queue) ClearResumeStep(ctx context.Context, itemID int64) error {
	if _, err := q.pool.Exec(ctx,
		`UPDATE request_item SET resume_from_step = NULL WHERE id = $1`, itemID); err != nil {
		return fmt.Errorf("сброс шага возобновления у пакета #%d: %w", itemID, err)
	}
	return nil
}

// Depth — сколько пакетов ждёт обработки. Для метрик и для диагностики.
func (q *Queue) Depth(ctx context.Context) (queued, running int, err error) {
	err = q.pool.QueryRow(ctx, `
		SELECT count(*) FILTER (WHERE status = 'queued'),
		       count(*) FILTER (WHERE status = 'running')
		FROM request_item
	`).Scan(&queued, &running)
	if err != nil {
		return 0, 0, fmt.Errorf("глубина очереди: %w", err)
	}
	return queued, running, nil
}

// Stuck — сколько пакетов ждут в очереди дольше minAge.
//
// Отдельно от Depth: глубина очереди сама по себе ни о чём не говорит — сто
// пакетов, разбираемых за минуту, это норма. Говорит то, что пакет ЛЕЖИТ:
// значит, его никто не забрал.
func (q *Queue) Stuck(ctx context.Context, minAge time.Duration) (int, error) {
	var count int
	err := q.pool.QueryRow(ctx, `
		SELECT count(*) FROM request_item
		WHERE status = 'queued' AND updated_at < now() - $1::interval
	`, minAge.String()).Scan(&count)
	if err != nil {
		return 0, fmt.Errorf("подсчёт залежавшихся пакетов: %w", err)
	}
	return count, nil
}

// Wait ждёт уведомления о новой задаче, но не дольше timeout.
//
// Отдельное подключение из пула: LISTEN — состояние сессии, и держать его на
// подключении, которое пул отдаст под обычный запрос, нельзя.
func (q *Queue) Wait(ctx context.Context, timeout time.Duration) error {
	conn, err := q.pool.Acquire(ctx)
	if err != nil {
		return fmt.Errorf("подключение для ожидания задач: %w", err)
	}
	defer conn.Release()

	if _, err := conn.Exec(ctx, "LISTEN "+Channel); err != nil {
		return fmt.Errorf("подписка на канал задач: %w", err)
	}

	waitCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	_, err = conn.Conn().WaitForNotification(waitCtx)
	switch {
	case err == nil:
		return nil
	case errors.Is(err, context.DeadlineExceeded):
		// Истёк таймаут ожидания — это не ошибка, а обычный тик опроса.
		return nil
	case errors.Is(err, context.Canceled) && ctx.Err() != nil:
		return ctx.Err()
	default:
		return fmt.Errorf("ожидание задач: %w", err)
	}
}

// --------------------------------------------------------------------------- исходы прогона

// Done снимает пакет с обработки после успешного прогона: счётчик неудач
// обнуляется, отметка шага возобновления снимается. Статус к этому моменту уже
// выставил сам конвейер, поэтому здесь он не трогается — иначе воркер затирал
// бы вердикт проверки.
func (q *Queue) Done(ctx context.Context, itemID int64) error {
	if _, err := q.pool.Exec(ctx,
		`UPDATE request_item SET resume_from_step = NULL, attempts = 0 WHERE id = $1`,
		itemID); err != nil {
		return fmt.Errorf("завершение пакета #%d: %w", itemID, err)
	}
	return nil
}

// Retry возвращает упавший пакет в очередь. Возвращает false, если попытки
// исчерпаны — тогда вызывающий обязан пометить пакет неудачей, а не оставить
// его крутиться.
//
// Повтор нужен потому, что большая часть сбоев здесь внешняя и временная:
// реестр не ответил, хранилище моргнуло, сеть до прокси. Безнадёжный случай
// (пакета нет в реестре) от временного отличается только тем, что повторы не
// помогают, — поэтому предел попыток, а не разбор текста ошибки.
func (q *Queue) Retry(ctx context.Context, itemID int64, maxAttempts int) (bool, error) {
	if maxAttempts <= 0 {
		maxAttempts = 3
	}
	var attempts int
	// Условие `status = 'running'` обязательно: пакет мог уйти из-под прогона,
	// пока он шёл. Самый частый случай — автор закрыл заявку (`cancelled`), и
	// без этой проверки упавший прогон вернул бы отменённый пакет в очередь,
	// то есть отмена не значила бы ничего. То же и с перехватом строки другим
	// воркером после таймаута: чужую работу переназначать нельзя.
	err := q.pool.QueryRow(ctx, `
		UPDATE request_item
		SET attempts = attempts + 1,
		    status = CASE WHEN attempts + 1 < $2 THEN 'queued' ELSE status END,
		    updated_at = now()
		WHERE id = $1 AND status = 'running'
		RETURNING attempts
	`, itemID, maxAttempts).Scan(&attempts)
	if errors.Is(err, pgx.ErrNoRows) {
		// Строка больше не наша. Не ошибка: просто делать с ней нечего.
		return false, ErrNotOurs
	}
	if err != nil {
		return false, fmt.Errorf("повтор пакета #%d: %w", itemID, err)
	}
	if attempts >= maxAttempts {
		return false, nil
	}
	return true, q.Notify(ctx)
}

// Fail помечает пакет неудачей окончательно. Причина уходит в карточку: без
// неё разработчик видит «не прошло» и не знает, что делать дальше.
func (q *Queue) Fail(ctx context.Context, itemID int64, reason, nextAction string) error {
	// Тот же guard, что в Retry: помечать неудачей можно только пакет, который
	// всё ещё за этим прогоном. Иначе закрытая автором заявка получила бы
	// «Ошибка проверки» от прогона, который уже никому не нужен.
	tag, err := q.pool.Exec(ctx, `
		UPDATE request_item
		SET status = 'failed', blocked_reason = $2, next_action = $3,
		    finished_at = now(), updated_at = now()
		WHERE id = $1 AND status = 'running'
	`, itemID, reason, nextAction)
	if err != nil {
		return fmt.Errorf("пометка пакета #%d неудачей: %w", itemID, err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotOurs
	}
	return nil
}
