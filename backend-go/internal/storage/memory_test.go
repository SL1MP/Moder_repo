package storage

import (
	"context"
	"strings"
	"testing"
)

func TestMemoryRoundTrip(t *testing.T) {
	ctx := context.Background()
	m := NewMemory("test")

	if _, err := m.Put(ctx, "a/b.txt", []byte("данные"), "text/plain"); err != nil {
		t.Fatalf("Put: %v", err)
	}
	data, err := m.Get(ctx, "a/b.txt")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if string(data) != "данные" {
		t.Errorf("Get = %q", data)
	}
	if _, err := m.Get(ctx, "нет"); !strings.Contains(err.Error(), ErrNotFound.Error()) {
		t.Errorf("отсутствующий объект дал %v, ожидалась ErrNotFound", err)
	}
	if err := m.Delete(ctx, "нет"); err != nil {
		t.Errorf("удаление отсутствующего дало ошибку: %v", err)
	}
}

// TestMemoryCopiesPayload — хранилище обязано отдавать то, что положили, даже
// если вызывающий переиспользовал буфер.
func TestMemoryCopiesPayload(t *testing.T) {
	ctx := context.Background()
	m := NewMemory("test")
	buf := []byte("исходное")
	if _, err := m.Put(ctx, "k", buf, ""); err != nil {
		t.Fatal(err)
	}
	copy(buf, "ЗАТЁРТО!")

	got, err := m.Get(ctx, "k")
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "исходное" {
		t.Errorf("содержимое изменилось вместе с буфером вызывающего: %q", got)
	}
	got[0] = 'X'
	again, _ := m.Get(ctx, "k")
	if again[0] == 'X' {
		t.Error("Get отдаёт ссылку на внутренний буфер — вызывающий может испортить хранилище")
	}
}

func TestMemoryListByPrefixSorted(t *testing.T) {
	ctx := context.Background()
	m := NewMemory("test")
	for _, key := range []string{"reports/2/a.json", "reports/1/a.json", "pypi/six/1.0/x.whl"} {
		if _, err := m.Put(ctx, key, []byte("x"), ""); err != nil {
			t.Fatal(err)
		}
	}
	objects, err := m.List(ctx, "reports/")
	if err != nil {
		t.Fatal(err)
	}
	if len(objects) != 2 {
		t.Fatalf("объектов %d, ожидалось 2", len(objects))
	}
	if objects[0].Key != "reports/1/a.json" {
		t.Errorf("список не отсортирован: %v", objects)
	}
}

func TestMemoryRejectsEmptyKey(t *testing.T) {
	if _, err := NewMemory("t").Put(context.Background(), "  ", []byte("x"), ""); err == nil {
		t.Error("пустой ключ принят")
	}
}
