// Package metrics — бизнес-метрики сервиса, отдаются на /metrics.
//
// Порт backend/app/core/metrics.py. Имена и метки держать 1:1 с ним, пока
// python-версия в эксплуатации: дашборды и алерты заказчика собраны по этим
// именам, и метрика, переименованная при переносе, — это молча опустевший
// график, а не ошибка, которую кто-то заметит.
//
// До появления этого пакета go-версия отдавала только стандартные коллекторы
// рантайма (память, горутины, GC). Снаружи /metrics при этом отвечал, и
// выглядело всё работающим — ровно тот случай, когда отсутствие наблюдаемости
// само себя не обнаруживает.
package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// StepTotal — результаты шагов конвейера.
//
// Метка manager есть и в python-версии: по ней видно, что сыплется конкретный
// менеджер, а не конвейер целиком. Без неё «шаг download отдаёт fail» не
// отличается от «реестр maven лежит».
var StepTotal = promauto.NewCounterVec(prometheus.CounterOpts{
	Name: "moderation_pipeline_step_total",
	Help: "Результаты шагов конвейера",
}, []string{"step", "result", "manager"})

// StepDuration — длительность шага.
var StepDuration = promauto.NewHistogramVec(prometheus.HistogramOpts{
	Name: "moderation_pipeline_step_duration_seconds",
	Help: "Длительность шага конвейера",
	// Разброс огромный: db_check — миллисекунды, download образа Docker —
	// минуты. Корзины по умолчанию (до 10 с) сложили бы всё тяжёлое в +Inf,
	// и увидеть разницу между «десять минут» и «час» было бы нельзя.
	Buckets: []float64{0.05, 0.25, 1, 5, 15, 60, 300, 900, 3600},
}, []string{"step"})

// ExternalCallTotal — вызовы внешних систем: реестров, артефактори, песочницы.
var ExternalCallTotal = promauto.NewCounterVec(prometheus.CounterOpts{
	Name: "moderation_external_call_total",
	Help: "Вызовы внешних сервисов",
}, []string{"service", "outcome"})

// CircuitState — состояние предохранителя по каждой внешней системе.
var CircuitState = promauto.NewGaugeVec(prometheus.GaugeOpts{
	Name: "moderation_circuit_state",
	Help: "Состояние circuit breaker (0=closed, 1=open, 2=half-open)",
}, []string{"service"})

// WorkerAlive — есть ли живой воркер, разбирающий очередь.
var WorkerAlive = promauto.NewGauge(prometheus.GaugeOpts{
	Name: "moderation_worker_alive",
	Help: "Есть ли живой воркер, разбирающий очередь (1/0)",
})

// StuckItems — пакеты, висящие в очереди дольше положенного.
var StuckItems = promauto.NewGauge(prometheus.GaugeOpts{
	Name: "moderation_pipeline_stuck_items",
	Help: "Пакеты, висящие в очереди дольше PIPELINE_STUCK_AFTER_SECONDS",
})

// WatchdogRecoveredTotal — пакеты, подобранные сторожем очереди.
//
// Метрика, по которой видно, что выделенный воркер не справляется: сторож —
// страховка, и её срабатывания не должны быть нормой.
var WatchdogRecoveredTotal = promauto.NewCounterVec(prometheus.CounterOpts{
	Name: "moderation_watchdog_recovered_total",
	Help: "Пакеты, подхваченные сторожем очереди",
}, []string{"mode"})

// OSVIndexAgeDays — возраст активного снапшота базы уязвимостей.
//
// Главная метрика для алерта: устаревший снапшот не роняет сервис, он тихо
// переводит каждый пакет на ручное решение DevSecOps. Снаружи это выглядит
// как «модерация стала медленной», а не как поломка.
var OSVIndexAgeDays = promauto.NewGauge(prometheus.GaugeOpts{
	Name: "moderation_osv_index_age_days",
	Help: "Возраст активного снапшота OSV в днях",
})

// ObserveStep записывает результат шага конвейера.
//
// Одна функция на обе метрики: раздельные вызовы рано или поздно
// расходятся — записали счётчик, забыли длительность, — и график длительности
// начинает врать, показывая только часть прогонов.
func ObserveStep(step, result, manager string, seconds float64) {
	StepTotal.WithLabelValues(step, result, manager).Inc()
	StepDuration.WithLabelValues(step).Observe(seconds)
}

// ObserveExternal записывает исход обращения к внешней системе.
func ObserveExternal(service, outcome string) {
	ExternalCallTotal.WithLabelValues(service, outcome).Inc()
}
