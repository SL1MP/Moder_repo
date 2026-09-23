package main

import (
	"os"
	"reflect"
	"testing"
)

// TestTakeLeadingKeepsFlagsParseable: путь, указанный перед флагами, не съедает
// сами флаги.
//
// Тест на первый взгляд лишний — он проверяет три строки. Но именно эти три
// строки закрывают поведение flag из стандартной библиотеки, которое молча
// теряет всё после первого позиционного аргумента: команда
// `import-packages список.txt --manager pypi` без них падала с «нужен
// --manager», хотя --manager указан. Ошибка выглядит как опечатка
// пользователя, а не как поведение разбора, и ищется долго.
func TestTakeLeadingKeepsFlagsParseable(t *testing.T) {
	cases := []struct {
		name    string
		args    []string
		leading string
		rest    []string
	}{
		{"путь перед флагами", []string{"список.txt", "--manager", "pypi"},
			"список.txt", []string{"--manager", "pypi"}},
		{"только флаги", []string{"--file", "список.txt"},
			"", []string{"--file", "список.txt"}},
		{"пусто", nil, "", nil},
		{"один путь", []string{"список.txt"}, "список.txt", []string{}},
		// Отрицательное значение флага не должно приниматься за путь: оно
		// начинается с дефиса и остаётся в аргументах разбора.
		{"флаг с дефисом", []string{"-manager=pypi"}, "", []string{"-manager=pypi"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			leading, rest := takeLeading(tc.args)
			if leading != tc.leading {
				t.Errorf("позиционный аргумент %q, ожидался %q", leading, tc.leading)
			}
			if !reflect.DeepEqual(rest, tc.rest) {
				t.Errorf("остаток %#v, ожидался %#v", rest, tc.rest)
			}
		})
	}
}

// TestSplitRolesDropsEmpty: «developer, ,devsecops» — это две роли, а не три.
//
// Пустая роль дошла бы до проверки по списку известных и завалила бы команду
// сообщением «неизвестная роль ««»», по которому непонятно, что не так с
// введённой строкой.
func TestSplitRolesDropsEmpty(t *testing.T) {
	got := splitRoles(" developer , ,devsecops,, ")
	want := []string{"developer", "devsecops"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("роли %#v, ожидались %#v", got, want)
	}
	if roles := splitRoles("   "); len(roles) != 0 {
		t.Fatalf("из пустой строки получились роли %#v", roles)
	}
}

// TestReadServicePasswordPrefersEnv: пароль берётся из окружения.
//
// Проверяется, что флага --password нет не только на словах: значение флага
// видно в `ps` любому пользователю машины и остаётся в истории оболочки, а
// пароль сервисной учётки — это право заводить заявки от имени CI.
func TestReadServicePasswordPrefersEnv(t *testing.T) {
	t.Setenv(servicePasswordEnv, "из-окружения")
	got, err := readServicePassword()
	if err != nil {
		t.Fatalf("пароль не прочитан: %v", err)
	}
	if got != "из-окружения" {
		t.Fatalf("пароль %q, ожидался «из-окружения»", got)
	}
}

// TestReadServicePasswordFromStdin: пароль можно передать по конвейеру.
func TestReadServicePasswordFromStdin(t *testing.T) {
	t.Setenv(servicePasswordEnv, "")
	withStdin(t, "по-конвейеру\n")
	got, err := readServicePassword()
	if err != nil {
		t.Fatalf("пароль не прочитан: %v", err)
	}
	if got != "по-конвейеру" {
		t.Fatalf("пароль %q, ожидался «по-конвейеру»", got)
	}
}

// TestReadServicePasswordRefusesEmpty: пустой ввод — ошибка, а не пустой
// пароль. Учётка с пустым паролем — это открытая дверь, заведённая молча.
func TestReadServicePasswordRefusesEmpty(t *testing.T) {
	t.Setenv(servicePasswordEnv, "")
	withStdin(t, "\n")
	if got, err := readServicePassword(); err == nil {
		t.Fatalf("пустой пароль принят: %q", got)
	}
}

// withStdin подменяет стандартный ввод на время теста.
func withStdin(t *testing.T, content string) {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("создание конвейера: %v", err)
	}
	if _, err := w.WriteString(content); err != nil {
		t.Fatalf("запись во ввод: %v", err)
	}
	w.Close()
	original := os.Stdin
	os.Stdin = r
	t.Cleanup(func() { os.Stdin = original; r.Close() })
}
