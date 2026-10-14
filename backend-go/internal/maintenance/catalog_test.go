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
		{"terraform", "registry.terraform.io/hashicorp/aws/5.31.0/terraform-provider-aws.zip", "hashicorp/aws", "5.31.0"},
	}
	for _, tt := range tests {
		t.Run(tt.manager+"/"+tt.name, func(t *testing.T) {
			got, ok := parseCatalogPath(tt.manager, tt.path)
			if !ok || got.Name != tt.name || got.Version != tt.version {
				t.Fatalf("parseCatalogPath(%q, %q) = %+v, %v; ожидалось %s@%s",
					t.manager, tt.path, got, ok, tt.name, tt.version)
			}
		})
	}
}

func TestParseCatalogPathSkipsMavenSidecars(t *testing.T) {
	for _, name := range []string{
		"x/1/x-1-sources.jar", "x/1/x-1-javadoc.jar", "x/1/x-1.jar.sha256", "x/1/x-1.jar.asc",
	} {
		if _, ok := parseCatalogPath("maven", "com/example/"+name); ok {
			t.Fatalf("исключённый Maven-файл распознан как пакет: %s", name)
		}
	}
}
