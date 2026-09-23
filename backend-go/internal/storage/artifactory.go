package storage

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"moderation/internal/artifactstore"
)

// Artifactory — хранилище поверх репозитория артефактори.
//
// Заменило S3. Причина не в том, что S3 плохо работал, а в том, что он был
// лишней системой: артефактори в контуре уже стоит, пакеты всё равно едут в
// него, и держать рядом второе хранилище значило админить, бэкапить и
// охранять два места вместо одного. Вдобавок промежуточная зона в артефактори
// делает публикацию переносом файла внутри одной системы (artifactstore.MoveFile)
// — той самой моделью, которой пользуется CI-версия, — вместо «скачать из S3 и
// выгрузить заново».
//
// Репозиторий обязан быть типа raw (generic у Artifactory): сюда кладутся
// файлы по произвольным путям, а не пакеты, и индексация формата им не нужна.
//
// Bucket() возвращает имя репозитория. Название метода осталось от S3 — его
// понимает вся вызывающая сторона, и переименование ради красоты стоило бы
// правок в местах, которые к хранилищу отношения не имеют.
type Artifactory struct {
	store artifactstore.Store
	repo  string
	// prefix — общий префикс всех ключей внутри репозитория. Пусто по
	// умолчанию; нужен, когда промежуточная зона и отчёты вынужденно живут в
	// одном репозитории (например, заказчику не дали завести второй).
	prefix string
}

// ArtifactoryConfig — параметры хранилища.
type ArtifactoryConfig struct {
	// Store — уже собранный клиент артефактори. Тот же, что публикует пакеты:
	// адрес, учётные данные и тип (nexus/generic) у них общие, и заводить
	// второе подключение к той же системе незачем.
	Store artifactstore.Store
	// Repo — репозиторий, в котором живут файлы.
	Repo string
	// Prefix — необязательный общий префикс ключей.
	Prefix string
}

// NewArtifactory собирает хранилище.
func NewArtifactory(cfg ArtifactoryConfig) (*Artifactory, error) {
	if cfg.Store == nil {
		return nil, fmt.Errorf("клиент артефактори не задан")
	}
	if strings.TrimSpace(cfg.Repo) == "" {
		return nil, fmt.Errorf("репозиторий артефактори для хранилища не задан")
	}
	return &Artifactory{
		store:  cfg.Store,
		repo:   strings.Trim(strings.TrimSpace(cfg.Repo), "/"),
		prefix: strings.Trim(strings.TrimSpace(cfg.Prefix), "/"),
	}, nil
}

// Repo — имя репозитория. Нужен вызывающему коду, который работает с
// артефактори напрямую: шаг публикации переносит файл из промежуточной зоны и
// обязан знать, откуда именно.
func (a *Artifactory) Repo() string { return a.repo }

// Path — полный путь ключа внутри репозитория, с учётом префикса. Тот же
// вызывающий код строит по нему адрес переноса.
func (a *Artifactory) Path(key string) string {
	key = strings.TrimPrefix(key, "/")
	if a.prefix == "" {
		return key
	}
	return a.prefix + "/" + key
}

func (a *Artifactory) Bucket() string { return a.repo }

// EnsureBucket ничего не создаёт: репозитории в артефактори заводит
// администратор, и создавать их от имени сервиса неправильно — у сервиса для
// этого и прав обычно нет.
//
// Проверка при этом настоящая: репозиторий, которого нет, обязан обнаружиться
// на старте, а не на первом пакете. Отсутствующий репозиторий — самая частая
// причина «пакет проверился и пропал», и молчать о нём нельзя.
func (a *Artifactory) EnsureBucket(ctx context.Context) error {
	// Обход пустого префикса отвечает и по существующему пустому репозиторию
	// (пустой список), и по несуществующему (ошибка) — этого достаточно, и
	// лишнего файла для проверки писать не надо.
	if _, err := a.store.ListFiles(ctx, a.repo, a.prefix); err != nil {
		return fmt.Errorf("репозиторий %q в артефактори недоступен: %w. "+
			"Заведите его как raw (generic) и дайте учётной записи сервиса права на запись", a.repo, err)
	}
	return nil
}

func (a *Artifactory) Put(ctx context.Context, key string, data []byte, contentType string) (Object, error) {
	path := a.Path(key)
	if err := a.store.WriteFile(ctx, a.repo, path, data, contentType); err != nil {
		return Object{}, err
	}
	return Object{
		Bucket: a.repo, Key: key,
		SizeBytes: int64(len(data)), ContentType: contentType,
	}, nil
}

func (a *Artifactory) Get(ctx context.Context, key string) ([]byte, error) {
	path := a.Path(key)
	// Сначала HEAD: ReadFile на отсутствующем файле вернёт обычную ошибку
	// «ответил 404», а вызывающий код обязан отличать «нет объекта» от «не
	// смогли спросить» — на первом он перекачивает артефакт, на втором зовёт
	// человека.
	file, err := a.store.StatFile(ctx, a.repo, path)
	if err != nil {
		return nil, err
	}
	if file == nil {
		return nil, fmt.Errorf("%w: %s/%s", ErrNotFound, a.repo, path)
	}
	return a.store.ReadFile(ctx, a.repo, path)
}

func (a *Artifactory) Stat(ctx context.Context, key string) (Object, error) {
	path := a.Path(key)
	file, err := a.store.StatFile(ctx, a.repo, path)
	if err != nil {
		return Object{}, err
	}
	if file == nil {
		return Object{}, fmt.Errorf("%w: %s/%s", ErrNotFound, a.repo, path)
	}
	return Object{
		Bucket: a.repo, Key: key,
		SizeBytes: file.SizeBytes, LastModified: file.LastModified,
	}, nil
}

// Delete удаляет объект. Отсутствие объекта — не ошибка: удаление обязано быть
// повторяемым, иначе повторный прогон уборки валится на том, что уже убрано.
func (a *Artifactory) Delete(ctx context.Context, key string) error {
	_, err := a.store.DeleteFile(ctx, a.repo, a.Path(key))
	return err
}

func (a *Artifactory) List(ctx context.Context, prefix string) ([]Object, error) {
	full := a.Path(prefix)
	files, err := a.store.ListFiles(ctx, a.repo, full)
	if err != nil {
		return nil, err
	}
	out := make([]Object, 0, len(files))
	for _, f := range files {
		key := strings.TrimPrefix(f.Path, "/")
		if a.prefix != "" {
			key = strings.TrimPrefix(strings.TrimPrefix(key, a.prefix), "/")
		}
		out = append(out, Object{
			Bucket: a.repo, Key: key,
			SizeBytes: f.SizeBytes, LastModified: f.LastModified,
		})
	}
	return out, nil
}

// Move переносит объект в другой репозиторий силами самого артефактори.
// errors.Is(err, artifactstore.ErrMoveUnsupported) — так нельзя, вызывающий
// обязан скачать и выгрузить сам.
func (a *Artifactory) Move(ctx context.Context, key, dstRepo, dstPath string) error {
	return a.store.MoveFile(ctx, a.repo, a.Path(key), dstRepo, dstPath)
}

// Staging — то, что шаг публикации знает о промежуточной зоне. Интерфейс, а не
// *Artifactory: в тестах конвейера зона в памяти, и переносить оттуда нечего.
type Staging interface {
	Store
	Repo() string
	Path(key string) string
	Move(ctx context.Context, key, dstRepo, dstPath string) error
}

var _ Staging = (*Artifactory)(nil)

// MoveUnsupported — удобная проверка для вызывающего кода, чтобы он не тянул
// импорт artifactstore ради одного errors.Is.
func MoveUnsupported(err error) bool {
	return errors.Is(err, artifactstore.ErrMoveUnsupported)
}
