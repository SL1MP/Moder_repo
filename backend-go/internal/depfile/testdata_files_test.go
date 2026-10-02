package depfile

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestSmallDependencyFiles(t *testing.T) {
	t.Parallel()
	_, source, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("не удалось определить путь теста")
	}
	root := filepath.Clean(filepath.Join(filepath.Dir(source), "..", "..", "..", "testdata", "dependency-files"))

	tests := []struct {
		manager string
		file    string
		name    string
		version string
	}{
		{"pypi", "pypi/requirements.txt", "requests", "2.31.0"},
		{"npm", "npm/package-lock.json", "lodash", "4.17.21"},
		{"go", "go/go.mod", "github.com/google/uuid", "v1.6.0"},
		{"nuget", "nuget/packages.config", "Newtonsoft.Json", "13.0.3"},
		{"maven", "maven/pom.xml", "org.apache.commons:commons-lang3", "3.14.0"},
		{"conan", "conan/conanfile.txt", "zlib", "1.3.1"},
		{"docker", "docker/Dockerfile", "postgres", "14.23@sha256:2f439458ab6a57a925825ae14f9d06910e4fe4a41c8d4a0ae06397e65b707e1b"},
		{"luarocks", "luarocks/moderation-test-1.0.0-1.rockspec", "luasocket", "3.1.0-1"},
		{"terraform", "terraform/.terraform.lock.hcl", "hashicorp/null", "3.2.2"},
		{"php", "php/composer.json", "psr/log", "3.0.0"},
	}

	for _, tc := range tests {
		t.Run(tc.manager, func(t *testing.T) {
			path := filepath.Join(root, filepath.FromSlash(tc.file))
			content, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			deps, err := Parse(tc.manager, filepath.Base(path), content)
			if err != nil {
				t.Fatal(err)
			}
			if len(deps) != 1 {
				t.Fatalf("получено зависимостей: %d, ожидалась одна: %#v", len(deps), deps)
			}
			if deps[0].Name != tc.name || deps[0].Version != tc.version || deps[0].Kind != KindDirect {
				t.Fatalf("получена зависимость %#v, ожидалась %s %s (%s)",
					deps[0], tc.name, tc.version, KindDirect)
			}
		})
	}
}
