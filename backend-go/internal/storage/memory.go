package storage

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"
)

// Memory — хранилище в памяти для тестов и для режима, в котором внешнее
// хранилище не поднято (локальная отладка конвейера).
//
// Не «мок»: это полноценная реализация контракта, включая ErrNotFound и
// независимость от порядка вызовов. Тест, прошедший на ней, проверяет логику
// шага, а не совпадение с заглушкой.
type Memory struct {
	mu      sync.RWMutex
	bucket  string
	objects map[string]memObject
	// Now подменяется в тестах, где важно время объекта.
	Now func() time.Time
}

type memObject struct {
	data        []byte
	contentType string
	modified    time.Time
}

func NewMemory(bucket string) *Memory {
	if bucket == "" {
		bucket = "moderation-artifacts"
	}
	return &Memory{bucket: bucket, objects: make(map[string]memObject)}
}

func (m *Memory) now() time.Time {
	if m.Now != nil {
		return m.Now()
	}
	return time.Now().UTC()
}

func (m *Memory) Bucket() string { return m.bucket }

func (m *Memory) EnsureBucket(context.Context) error { return nil }

func (m *Memory) Put(_ context.Context, key string, data []byte, contentType string) (Object, error) {
	if strings.TrimSpace(key) == "" {
		return Object{}, fmt.Errorf("пустой ключ объекта")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	// Копируем: вызывающий волен переиспользовать буфер, а хранилище обязано
	// отдавать то, что положили.
	stored := append([]byte(nil), data...)
	m.objects[key] = memObject{data: stored, contentType: contentType, modified: m.now()}
	return Object{
		Bucket: m.bucket, Key: key, SizeBytes: int64(len(stored)),
		ContentType: contentType, LastModified: m.objects[key].modified,
	}, nil
}

func (m *Memory) Get(_ context.Context, key string) ([]byte, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	obj, ok := m.objects[key]
	if !ok {
		return nil, fmt.Errorf("%w: %s", ErrNotFound, key)
	}
	return append([]byte(nil), obj.data...), nil
}

func (m *Memory) Stat(_ context.Context, key string) (Object, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	obj, ok := m.objects[key]
	if !ok {
		return Object{}, fmt.Errorf("%w: %s", ErrNotFound, key)
	}
	return Object{
		Bucket: m.bucket, Key: key, SizeBytes: int64(len(obj.data)),
		ContentType: obj.contentType, LastModified: obj.modified,
	}, nil
}

// Delete — удаление отсутствующего объекта не ошибка: шаг публикации вызывает
// его и при повторном прогоне, когда объект уже вычищен.
func (m *Memory) Delete(_ context.Context, key string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.objects, key)
	return nil
}

func (m *Memory) List(_ context.Context, prefix string) ([]Object, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	var out []Object
	for key, obj := range m.objects {
		if !strings.HasPrefix(key, prefix) {
			continue
		}
		out = append(out, Object{
			Bucket: m.bucket, Key: key, SizeBytes: int64(len(obj.data)),
			ContentType: obj.contentType, LastModified: obj.modified,
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Key < out[j].Key })
	return out, nil
}
