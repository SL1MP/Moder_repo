package maintenance

import "testing"

func TestParseCatalogPath(t *testing.T) {
	tests := []struct {
		manager, path, name, version string
	}{
		{"pypi", "aenum/2.2.4/aenum-2.2.4-py3-none-any.whl", "aenum", "2.2.4"},
		{"pypi", ".pypi/requests/requests-2.31.0.tar.gz", "requests", "2.31.0"},
		{"npm", "lodash/-/lodash-4.17.21.tgz", "lodash", "4.17.21"},
		{"npm", "@babel/core/-/core-7.24.0.tgz", "@babel/core", "7.24.0"},
		{"go", "github.com/!sirupsen/logrus/@v/v1.9.3.zip", "github.com/Sirupsen/logrus", "v1.9.3"},
		{"maven", "org/apache/commons/commons-lang3/3.14.0/commons-lang3-3.14.0.jar", "org.apache.commons:commons-lang3", "3.14.0"},
		{"nuget", "newtonsoft.json/13.0.3/newtonsoft.json.13.0.3.nupkg", "newtonsoft.json", "13.0.3"},
		{"docker", "postgres/14.23/list.manifest.json", "postgres", "14.23"},
		{"docker", "mcr.microsoft.com/dotnet/aspnet/10.0/manifest.json", "mcr.microsoft.com/dotnet/aspnet", "10.0"},
		{"conan", "boost/1.90.0/boost-1.90.0.tgz", "boost", "1.90.0"},
		{"conan", "boost/1.90.0/_/_/67c04388906d183b7bf506954ab/export/conan_export.tgz", "boost", "1.90.0"},
		{"luarocks", "lua-cjson-2.1.0.10-1.src.rock", "lua-cjson", "2.1.0.10-1"},
		{"php", "symfony/console/v7.2.1/symfony-console-v7.2.1.zip", "symfony/console", "v7.2.1"},
		{"terraform", "registry.terraform.io/hashicorp/aws/5.31.0/terraform-provider-aws.zip", "hashicorp/aws", "5.31.0"},
	}
	for _, tt := range tests {
		t.Run(tt.manager+"/"+tt.name, func(t *testing.T) {
			got, ok := parseCatalogPath(tt.manager, tt.path)
			if !ok || got.Name != tt.name || got.Version != tt.version {
				t.Fatalf("parseCatalogPath(%q, %q) = %+v, %v; ожидалось %s@%s",
					tt.manager, tt.path, got, ok, tt.name, tt.version)
			}
		})
	}
}

func TestParseCatalogPathSkipsDockerDigestCopies(t *testing.T) {
	for _, file := range []string{
		"postgres/sha256:0123456789abcdef/manifest.json",
		"postgres/14.23/blobs/sha256/0123456789abcdef",
	} {
		if _, ok := parseCatalogPath("docker", file); ok {
			t.Fatalf("технический Docker-объект распознан как тег: %s", file)
		}
	}
}

func TestParseCatalogPathSkipsMavenSidecars(t *testing.T) {
	for _, name := range []string{
		"x/1/x-1-sources.jar", "x/1/x-1-javadoc.jar", "x/1/x-1.jar.md5",
		"x/1/x-1.jar.sha1", "x/1/x-1.jar.sha256", "x/1/x-1.jar.sha512", "x/1/x-1.jar.asc",
	} {
		if _, ok := parseCatalogPath("maven", "com/example/"+name); ok {
			t.Fatalf("исключённый Maven-файл распознан как пакет: %s", name)
		}
	}
}

func TestParseCatalogPathKeepsEveryPyPIWheel(t *testing.T) {
	for _, filename := range []string{
		"lz4-4.4.5-cp38-cp38-win_amd64.whl",
		"lz4-4.4.5-cp313-cp313-manylinux_2_17_x86_64.whl",
		"lz4-4.4.5-cp314-cp314-win_amd64.whl",
	} {
		got, ok := parseCatalogPath("pypi", "lz4/4.4.5/"+filename)
		if !ok || got.Name != "lz4" || got.Version != "4.4.5" {
			t.Fatalf("wheel %s не распознан: %+v, %v", filename, got, ok)
		}
	}
}
