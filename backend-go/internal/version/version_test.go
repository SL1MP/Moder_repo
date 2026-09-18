package version

import (
	"errors"
	"testing"
)

func TestSemverCompare(t *testing.T) {
	s := Semver{}
	cases := []struct {
		a, b string
		want int
	}{
		{"1.2.3", "1.2.3", 0},
		{"1.2", "1.2.0", 0},
		{"1.2.4", "1.2.3", 1},
		{"1.10.0", "1.9.0", 1},
		{"2.0.0", "10.0.0", -1},
		{"1.0.0-alpha", "1.0.0", -1},
		{"1.0.0-alpha", "1.0.0-alpha.1", -1},
		{"1.0.0-alpha.1", "1.0.0-alpha.beta", -1},
		{"1.0.0-beta", "1.0.0-rc.1", -1},
		{"1.0.0+build", "1.0.0", 0},
		{"v1.2.3", "1.2.3", 0},
	}
	for _, c := range cases {
		if got := s.Compare(c.a, c.b); got != c.want {
			t.Errorf("Compare(%q, %q) = %d, ожидалось %d", c.a, c.b, got, c.want)
		}
		if got := s.Compare(c.b, c.a); got != -c.want {
			t.Errorf("Compare(%q, %q) = %d, ожидалось %d (обратный порядок)", c.b, c.a, got, -c.want)
		}
	}
}

func TestSemverSatisfies(t *testing.T) {
	s := Semver{}
	cases := []struct {
		constraint, version string
		want                bool
	}{
		{"^1.2.3", "1.2.3", true},
		{"^1.2.3", "1.9.0", true},
		{"^1.2.3", "2.0.0", false},
		{"^1.2.3", "1.2.2", false},
		{"^0.2.3", "0.2.9", true},
		{"^0.2.3", "0.3.0", false},
		{"^0.0.3", "0.0.3", true},
		{"^0.0.3", "0.0.4", false},
		{"^0", "0.9.9", true},
		{"^0", "1.0.0", false},
		{"~1.2.3", "1.2.9", true},
		{"~1.2.3", "1.3.0", false},
		{"~1.2", "1.2.9", true},
		{"~1.2", "1.3.0", false},
		{"~1", "1.9.9", true},
		{"~1", "2.0.0", false},
		{"1.2.x", "1.2.9", true},
		{"1.2.x", "1.3.0", false},
		{"1.x", "1.9.9", true},
		{"*", "42.0.0", true},
		{"", "42.0.0", true},
		{">=1.0.0 <2.0.0", "1.5.0", true},
		{">=1.0.0 <2.0.0", "2.0.0", false},
		{"1.2.3 - 2.3.4", "2.3.4", true},
		{"1.2.3 - 2.3.4", "2.3.5", false},
		{"1.2.3 - 2.3", "2.3.9", true},
		{"1.2.3 - 2.3", "2.4.0", false},
		{"^1.0.0 || ^2.0.0", "2.5.0", true},
		{"^1.0.0 || ^2.0.0", "3.0.0", false},
		{"6.11.0", "6.11.0", true},
		{"6.11.0", "6.11.1", false},
		{">=2", "2.0.0", true},
		{">=2", "1.9.9", false},
		{">2", "3.0.0", true},
		{">2", "2.5.0", false},
		{"<2", "1.9.9", true},
		{"<2", "2.0.0", false},
		// Пререлиз не подставляется в диапазон, который его не называл:
		// иначе ^1.0.0 затянул бы 2.0.0-rc1 через нижнюю границу.
		{"^1.0.0", "2.0.0-rc1", false},
		{">=1.0.0", "2.0.0-rc1", false},
		{">=1.0.0-rc1 <2.0.0", "1.0.0-rc2", true},
		{"^1.0.0-rc1", "1.0.0-rc2", true},
	}
	for _, c := range cases {
		got, err := s.Satisfies(c.constraint, c.version)
		if err != nil {
			t.Fatalf("Satisfies(%q, %q): %v", c.constraint, c.version, err)
		}
		if got != c.want {
			t.Errorf("Satisfies(%q, %q) = %v, ожидалось %v", c.constraint, c.version, got, c.want)
		}
	}
}

func TestSemverSelectTakesHighestStable(t *testing.T) {
	s := Semver{}
	available := []string{"1.0.0", "1.4.2", "1.9.9", "2.0.0", "2.1.0-rc1"}

	got, err := s.Select("^1.0.0", available)
	if err != nil || got != "1.9.9" {
		t.Fatalf("Select(^1.0.0) = %q, %v; ожидалось 1.9.9", got, err)
	}
	if got, err := s.Select(">=2.0.0", available); err != nil || got != "2.0.0" {
		t.Fatalf("Select(>=2.0.0) = %q, %v; ожидалось 2.0.0 (пререлиз не берём)", got, err)
	}
	// Ни одного стабильного релиза — пререлиз лучше потерянной зависимости.
	if got, err := s.Select("^2.0.0", []string{"2.1.0-rc1"}); err != nil || got != "2.1.0-rc1" {
		t.Fatalf("Select при отсутствии релизов = %q, %v; ожидался пререлиз", got, err)
	}
	if _, err := s.Select("^9.0.0", available); !errors.Is(err, ErrNoMatch) {
		t.Fatalf("Select(^9.0.0) должен вернуть ErrNoMatch, получено %v", err)
	}
}

func TestPEP440Compare(t *testing.T) {
	p := PEP440{}
	cases := []struct {
		a, b string
		want int
	}{
		{"1.0", "1.0.0", 0},
		{"2.31.0", "2.30.0", 1},
		{"1.0a1", "1.0", -1},
		{"1.0a1", "1.0b1", -1},
		{"1.0b1", "1.0rc1", -1},
		{"1.0rc1", "1.0", -1},
		{"1.0", "1.0.post1", -1},
		{"1.0.dev1", "1.0a1", -1},
		{"1.0.dev1", "1.0", -1},
		{"1!1.0", "2.0", 1},
		{"1.0+local", "1.0", 0},
		{"2023.7.22", "2023.5.7", 1},
	}
	for _, c := range cases {
		if got := p.Compare(c.a, c.b); got != c.want {
			t.Errorf("Compare(%q, %q) = %d, ожидалось %d", c.a, c.b, got, c.want)
		}
		if got := p.Compare(c.b, c.a); got != -c.want {
			t.Errorf("Compare(%q, %q) = %d, ожидалось %d (обратный порядок)", c.b, c.a, got, -c.want)
		}
	}
}

func TestPEP440Satisfies(t *testing.T) {
	p := PEP440{}
	cases := []struct {
		constraint, version string
		want                bool
	}{
		{">=2,<4", "3.3.2", true},
		{">=2,<4", "4.0.0", false},
		{">=2,<4", "1.9", false},
		{"==1.4.2", "1.4.2", true},
		{"==1.4.*", "1.4.9", true},
		{"==1.4.*", "1.5.0", false},
		{"!=1.5.7,>=1.5.6", "1.5.7", false},
		{"!=1.5.7,>=1.5.6", "1.5.8", true},
		{"~=1.4.2", "1.4.9", true},
		{"~=1.4.2", "1.5.0", false},
		{"~=1.4.2", "1.4.1", false},
		{">=1.21.1,<3", "2.0.7", true},
		{"", "9.9.9", true},
		{">=2017.4.17", "2023.7.22", true},
	}
	for _, c := range cases {
		got, err := p.Satisfies(c.constraint, c.version)
		if err != nil {
			t.Fatalf("Satisfies(%q, %q): %v", c.constraint, c.version, err)
		}
		if got != c.want {
			t.Errorf("Satisfies(%q, %q) = %v, ожидалось %v", c.constraint, c.version, got, c.want)
		}
	}
}

func TestPEP440SelectSkipsPrerelease(t *testing.T) {
	p := PEP440{}
	available := []string{"1.26.18", "2.0.0", "2.1.0", "2.2.0rc1", "2.2.0.dev1"}
	got, err := p.Select(">=1.21.1,<3", available)
	if err != nil || got != "2.1.0" {
		t.Fatalf("Select = %q, %v; ожидалось 2.1.0 (пререлиз и dev не берём)", got, err)
	}
	if got, err := p.Select(">=2.2.0rc1", available); err != nil || got != "2.2.0rc1" {
		t.Fatalf("Select с пререлизом в требовании = %q, %v; ожидалось 2.2.0rc1", got, err)
	}
}

func TestNuGetRanges(t *testing.T) {
	n := NuGet{}
	cases := []struct {
		constraint, version string
		want                bool
	}{
		{"1.0", "1.0", true},
		{"1.0", "2.0", true}, // голая версия — это «не ниже»
		{"1.0", "0.9", false},
		{"[1.0]", "1.0", true},
		{"[1.0]", "1.0.1", false},
		{"[1.0,2.0)", "1.5", true},
		{"[1.0,2.0)", "2.0", false},
		{"(1.0,2.0]", "1.0", false},
		{"(1.0,2.0]", "2.0", true},
		{"(,2.0]", "0.1", true},
		{"[1.0,)", "99.0", true},
		{"4.3.0", "4.3.0", true},
	}
	for _, c := range cases {
		got, err := n.Satisfies(c.constraint, c.version)
		if err != nil {
			t.Fatalf("Satisfies(%q, %q): %v", c.constraint, c.version, err)
		}
		if got != c.want {
			t.Errorf("Satisfies(%q, %q) = %v, ожидалось %v", c.constraint, c.version, got, c.want)
		}
	}
}

// NuGet резолвит в минимальную подходящую версию — в отличие от npm и pip.
func TestNuGetSelectTakesLowest(t *testing.T) {
	n := NuGet{}
	available := []string{"4.0.0", "4.3.0", "4.5.0", "5.0.0"}
	got, err := n.Select("4.3.0", available)
	if err != nil || got != "4.3.0" {
		t.Fatalf("Select = %q, %v; ожидалось 4.3.0", got, err)
	}
	if got, err := n.Select("[4.0,5.0)", available); err != nil || got != "4.0.0" {
		t.Fatalf("Select = %q, %v; ожидалось 4.0.0", got, err)
	}
}

func TestGoModExactOnly(t *testing.T) {
	g := GoMod{}
	if got, err := g.Select("v1.2.3", nil); err != nil || got != "v1.2.3" {
		t.Fatalf("Select без списка = %q, %v", got, err)
	}
	if _, err := g.Select("v1.2.3", []string{"v1.2.4"}); !errors.Is(err, ErrNoMatch) {
		t.Fatalf("версии нет в реестре — ожидался ErrNoMatch, получено %v", err)
	}
	if g.Compare("v0.0.0-20221227161230-091c0ba34f0a", "v1.0.0") >= 0 {
		t.Error("псевдоверсия должна быть младше релиза")
	}
	if !g.IsPrerelease("v0.0.0-20221227161230-091c0ba34f0a") {
		t.Error("псевдоверсия — это пререлиз")
	}
}

func TestBadConstraintIsNamed(t *testing.T) {
	if _, err := (PEP440{}).Satisfies("примерно 1.0", "1.0"); !errors.Is(err, ErrBadConstraint) {
		t.Fatalf("ожидался ErrBadConstraint, получено %v", err)
	}
	if _, err := (NuGet{}).Satisfies("[1.0,2.0", "1.5"); !errors.Is(err, ErrBadConstraint) {
		t.Fatalf("незакрытый интервал должен называться ошибкой, получено %v", err)
	}
}

func TestForKnowsEveryManager(t *testing.T) {
	for _, manager := range []string{"pypi", "npm", "go", "nuget"} {
		scheme, err := For(manager)
		if err != nil {
			t.Fatalf("For(%q): %v", manager, err)
		}
		if scheme.Name() != manager {
			t.Errorf("For(%q).Name() = %q", manager, scheme.Name())
		}
	}
	if _, err := For("maven"); err == nil {
		t.Error("для нереализованного менеджера ожидалась ошибка")
	}
}
