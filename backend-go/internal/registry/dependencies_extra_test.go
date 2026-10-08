package registry_test

import (
	"context"
	"strings"
	"testing"

	"moderation/internal/registry"
)

func TestDependencyResolverMatrix(t *testing.T) {
	reg := registry.New(registry.Config{HTTP: &fakeRegistry{responses: map[string]string{}}})
	want := map[string]bool{
		"pypi": true, "npm": true, "go": true, "nuget": true,
		"conan": true, "luarocks": true, "maven": true, "php": true, "terraform": true,
		"docker": false, "git": false, "files": false,
	}
	for manager, expected := range want {
		plugin, err := reg.Get(manager)
		if err != nil {
			t.Fatalf("Get(%s): %v", manager, err)
		}
		_, supported := plugin.(registry.DependencyResolver)
		if supported != expected {
			t.Errorf("%s: DependencyResolver=%v, ожидалось %v", manager, supported, expected)
		}
	}
}

func TestMavenResolvesEffectivePOM(t *testing.T) {
	f := &fakeRegistry{responses: map[string]string{
		"https://maven.test/org/example/app/1.0.0/app-1.0.0.pom": `<project>
			<parent><groupId>org.example</groupId><artifactId>parent</artifactId><version>1.0.0</version></parent>
			<artifactId>app</artifactId>
			<properties><api.version>3.2.1</api.version></properties>
			<dependencies>
			  <dependency><groupId>org.libs</groupId><artifactId>core</artifactId></dependency>
			  <dependency><groupId>org.libs</groupId><artifactId>api</artifactId><version>${api.version}</version></dependency>
			  <dependency><groupId>org.libs</groupId><artifactId>tests</artifactId><version>1.0.0</version><scope>test</scope></dependency>
			  <dependency><groupId>org.libs</groupId><artifactId>optional</artifactId><version>1.0.0</version><optional>true</optional></dependency>
			</dependencies>
		</project>`,
		"https://maven.test/org/example/parent/1.0.0/parent-1.0.0.pom": `<project>
			<groupId>org.example</groupId><artifactId>parent</artifactId><version>1.0.0</version>
			<properties><core.version>2.1.0</core.version></properties>
			<dependencyManagement><dependencies><dependency>
			  <groupId>org.libs</groupId><artifactId>core</artifactId><version>${core.version}</version>
			</dependency></dependencies></dependencyManagement>
		</project>`,
		"https://maven.test/org/libs/core/maven-metadata.xml": `<metadata><versioning><versions>
			<version>2.0.0</version><version>2.1.0</version><version>2.2.0-SNAPSHOT</version>
		</versions></versioning></metadata>`,
	}}
	plugin := pluginWith(t, "maven", f)
	resolver := plugin.(registry.DependencyResolver)
	ref, err := registry.ParseEntry(plugin, "org.example:app:1.0.0")
	if err != nil {
		t.Fatal(err)
	}
	requirements, err := resolver.Requirements(context.Background(), ref)
	if err != nil {
		t.Fatal(err)
	}
	if len(requirements) != 3 {
		t.Fatalf("Maven зависимости: %+v", requirements)
	}
	byName := map[string]registry.Requirement{}
	for _, requirement := range requirements {
		byName[requirement.Name] = requirement
	}
	if byName["org.libs:core"].Constraint != "2.1.0" {
		t.Errorf("managed версия core = %q", byName["org.libs:core"].Constraint)
	}
	if byName["org.libs:api"].Constraint != "3.2.1" {
		t.Errorf("property версия api = %q", byName["org.libs:api"].Constraint)
	}
	if !byName["org.libs:optional"].Optional {
		t.Error("optional dependency не помечена optional")
	}
	versions, err := resolver.Versions(context.Background(), "org.libs:core")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(versions, ",") != "2.0.0,2.1.0" {
		t.Errorf("Maven versions = %v", versions)
	}
}

func TestLuaRocksReadsDependenciesAndManifest(t *testing.T) {
	f := &fakeRegistry{responses: map[string]string{
		"https://luarocks.test/myrock-1.2.0-1.rockspec": `package = "myrock"
			version = "1.2.0-1"
			dependencies = { "lua >= 5.1", "luasocket >= 3.0, < 4.0", "lpeg ~> 1.0" }`,
		"https://luarocks.test/manifest": `repository = {
			["luasocket"] = { ["3.0.0-1"] = {}, ["3.1.0-1"] = {} },
			["lpeg"] = { ["1.0.2-1"] = {} }
		}`,
	}}
	plugin := pluginWith(t, "luarocks", f)
	resolver := plugin.(registry.DependencyResolver)
	ref, _ := registry.ParseEntry(plugin, "myrock@1.2.0-1")
	requirements, err := resolver.Requirements(context.Background(), ref)
	if err != nil {
		t.Fatal(err)
	}
	if len(requirements) != 2 || requirements[0].Name != "luasocket" || requirements[1].Name != "lpeg" {
		t.Fatalf("LuaRocks зависимости: %+v", requirements)
	}
	versions, err := resolver.Versions(context.Background(), "luasocket")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(versions, ",") != "3.0.0-1,3.1.0-1" {
		t.Errorf("LuaRocks versions = %v", versions)
	}
}

func TestComposerReadsRuntimeRequires(t *testing.T) {
	f := &fakeRegistry{responses: map[string]string{
		"https://packagist.test/p2/acme/app.json": `{"packages":{"acme/app":[{
			"version":"1.2.0","version_normalized":"1.2.0.0",
			"require":{"php":"^8.2","ext-json":"*","psr/log":"^3.0","symfony/console":"^6.4"}
		}]}}`,
	}}
	plugin := pluginWith(t, "php", f)
	resolver := plugin.(registry.DependencyResolver)
	ref, _ := registry.ParseEntry(plugin, "acme/app:1.2.0")
	requirements, err := resolver.Requirements(context.Background(), ref)
	if err != nil {
		t.Fatal(err)
	}
	if len(requirements) != 2 || requirements[0].Name != "psr/log" || requirements[1].Name != "symfony/console" {
		t.Fatalf("Composer зависимости: %+v", requirements)
	}
	versions, err := resolver.Versions(context.Background(), "acme/app")
	if err != nil || len(versions) != 1 || versions[0] != "1.2.0" {
		t.Fatalf("Composer versions: %v, %v", versions, err)
	}
}

func TestTerraformProviderHasVerifiedEmptyGraph(t *testing.T) {
	f := &fakeRegistry{responses: map[string]string{
		"https://terraform.test/v1/providers/hashicorp/null/versions": `{
			"versions":[{"version":"3.2.2","platforms":[{"os":"linux","arch":"amd64"}]}]}`,
	}}
	plugin := pluginWith(t, "terraform", f)
	resolver := plugin.(registry.DependencyResolver)
	ref, _ := registry.ParseEntry(plugin, "hashicorp/null@3.2.2")
	requirements, err := resolver.Requirements(context.Background(), ref)
	if err != nil || len(requirements) != 0 {
		t.Fatalf("Terraform dependencies = %v, %v", requirements, err)
	}
	versions, err := resolver.Versions(context.Background(), "hashicorp/null")
	if err != nil || len(versions) != 1 || versions[0] != "3.2.2" {
		t.Fatalf("Terraform versions = %v, %v", versions, err)
	}
}
