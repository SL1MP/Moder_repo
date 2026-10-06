package depfile_test

import (
	"fmt"
	"testing"

	"moderation/internal/depfile"
	"moderation/internal/registry"
)

// TestEveryDeclaredDependencyFileParses — контракт между выпадающим списком
// файлов (registry.DependencyFiles) и настоящим парсером. Раньше Docker
// объявлял docker-compose.*, а Composer — composer.lock, хотя depfile их
// отвергал. Такой разъезд должен ломать тест до выкладки, а не файл
// разработчика в интерфейсе.
func TestEveryDeclaredDependencyFileParses(t *testing.T) {
	type fixture struct {
		manager string
		pattern string
		filename string
		content string
		name    string
		version string
	}
	digest := "2f439458ab6a57a925825ae14f9d06910e4fe4a41c8d4a0ae06397e65b707e1b"
	fixtures := []fixture{
		{"pypi", "requirements*.txt", "requirements-dev.txt", "requests==2.31.0\n", "requests", "2.31.0"},
		{"pypi", "poetry.lock", "poetry.lock", "[[package]]\nname=\"requests\"\nversion=\"2.31.0\"\n", "requests", "2.31.0"},
		{"pypi", "pyproject.toml", "pyproject.toml", "[project]\ndependencies=[\"requests==2.31.0\"]\n", "requests", "2.31.0"},

		{"npm", "package-lock.json", "package-lock.json", `{"lockfileVersion":3,"packages":{"":{"dependencies":{"lodash":"4.17.21"}},"node_modules/lodash":{"version":"4.17.21"}}}`, "lodash", "4.17.21"},
		{"npm", "yarn.lock", "yarn.lock", "lodash@^4.17.0:\n  version \"4.17.21\"\n", "lodash", "4.17.21"},
		{"npm", "package.json", "package.json", `{"dependencies":{"lodash":"4.17.21"}}`, "lodash", "4.17.21"},

		{"go", "go.mod", "go.mod", "module example.test/app\nrequire github.com/google/uuid v1.6.0\n", "github.com/google/uuid", "v1.6.0"},
		{"go", "go.sum", "go.sum", "github.com/google/uuid v1.6.0 h1:test=\n", "github.com/google/uuid", "v1.6.0"},

		{"nuget", "packages.lock.json", "packages.lock.json", `{"version":1,"dependencies":{"net8.0":{"Newtonsoft.Json":{"type":"Direct","resolved":"13.0.3"}}}}`, "Newtonsoft.Json", "13.0.3"},
		{"nuget", "packages.config", "packages.config", "Newtonsoft.Json@13.0.3\n", "Newtonsoft.Json", "13.0.3"},
		{"nuget", "*.csproj", "App.csproj", `<Project><ItemGroup><PackageReference Include="Newtonsoft.Json" Version="13.0.3" /></ItemGroup></Project>`, "Newtonsoft.Json", "13.0.3"},

		{"conan", "conanfile.txt", "conanfile.txt", "[requires]\nzlib/1.3.1\n", "zlib", "1.3.1"},
		{"conan", "conanfile.py", "conanfile.py", `def requirements(self): self.requires("zlib/1.3.1")`, "zlib", "1.3.1"},
		{"conan", "conan.lock", "conan.lock", `{"requires":["zlib/1.3.1#revision"]}`, "zlib", "1.3.1"},

		{"docker", "Dockerfile", "Dockerfile", "FROM postgres:14.23@sha256:" + digest + "\n", "postgres", "14.23@sha256:" + digest},
		{"docker", "docker-compose.yml", "docker-compose.yml", "services:\n  db:\n    image: postgres:14.23@sha256:" + digest + "\n", "postgres", "14.23@sha256:" + digest},
		{"docker", "docker-compose.yaml", "docker-compose.yaml", "services:\n  db:\n    image: postgres:14.23@sha256:" + digest + "\n", "postgres", "14.23@sha256:" + digest},

		{"luarocks", "*.rockspec", "demo-1.0.0-1.rockspec", `dependencies = { "luasocket == 3.1.0-1" }`, "luasocket", "3.1.0-1"},

		{"maven", "pom.xml", "pom.xml", `<project><dependencies><dependency><groupId>org.apache.commons</groupId><artifactId>commons-lang3</artifactId><version>3.14.0</version></dependency></dependencies></project>`, "org.apache.commons:commons-lang3", "3.14.0"},
		{"maven", "build.gradle", "build.gradle", `dependencies { implementation 'org.apache.commons:commons-lang3:3.14.0' }`, "org.apache.commons:commons-lang3", "3.14.0"},
		{"maven", "build.gradle.kts", "build.gradle.kts", `dependencies { implementation("org.apache.commons:commons-lang3:3.14.0") }`, "org.apache.commons:commons-lang3", "3.14.0"},

		{"php", "composer.json", "composer.json", `{"require":{"psr/log":"3.0.0"}}`, "psr/log", "3.0.0"},
		{"php", "composer.lock", "composer.lock", `{"packages":[{"name":"psr/log","version":"3.0.0"}]}`, "psr/log", "3.0.0"},

		{"terraform", ".terraform.lock.hcl", ".terraform.lock.hcl", "hashicorp/null@3.2.2\n", "hashicorp/null", "3.2.2"},
		{"terraform", "versions.tf", "versions.tf", "source = \"hashicorp/null\"\nversion = \"= 3.2.2\"\n", "hashicorp/null", "3.2.2"},
		{"terraform", "providers.tf", "providers.tf", "source = \"hashicorp/null\"\nversion = \"= 3.2.2\"\n", "hashicorp/null", "3.2.2"},
	}

	byKey := make(map[string]fixture, len(fixtures))
	for _, item := range fixtures {
		key := item.manager + "/" + item.pattern
		if _, duplicate := byKey[key]; duplicate {
			t.Fatalf("дублирующий fixture %s", key)
		}
		byKey[key] = item
	}

	reg := registry.New(registry.Config{})
	declared := map[string]bool{}
	for _, plugin := range reg.Plugins() {
		for _, pattern := range plugin.DependencyFiles() {
			key := plugin.Code() + "/" + pattern
			declared[key] = true
			item, ok := byKey[key]
			if !ok {
				t.Errorf("для объявленного формата %s нет проверки", key)
				continue
			}
			t.Run(fmt.Sprintf("%s/%s", item.manager, item.filename), func(t *testing.T) {
				deps, err := depfile.Parse(item.manager, item.filename, []byte(item.content))
				if err != nil {
					t.Fatal(err)
				}
				found := false
				for _, dependency := range deps {
					if dependency.Name == item.name && dependency.Version == item.version {
						found = true
						break
					}
				}
				if !found {
					t.Fatalf("получено %#v, ожидалась %s %s", deps, item.name, item.version)
				}
			})
		}
	}
	for key := range byKey {
		if !declared[key] {
			t.Errorf("fixture %s есть, но формат не объявлен плагином", key)
		}
	}
}
