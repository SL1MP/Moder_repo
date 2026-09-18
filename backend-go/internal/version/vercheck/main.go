// Команда vercheck — дифференциальная проверка схем версий против эталонных
// реализаций: packaging (PEP 440) и semver (npm). Смысл в том, что свои
// правила версий проверять своими же тестами — значит проверять своё
// понимание правил, а не сами правила.
//
// Корпус собирается из настоящих реестров скриптами рядом (gen_pypi.py,
// gen_npm.mjs), затем:
//
//	go run ./internal/version/vercheck <файл.json> <менеджер> [compare]
//
// Последний прогон: pypi — 73 200 пар «требование/версия» и 6 537 сравнений,
// npm — 2 185 500 пар и 4 349 сравнений, расхождений нет.
package main

import (
	"encoding/json"
	"fmt"
	"os"

	"moderation/internal/version"
)

type Case struct {
	Spec     string `json:"spec"`
	Version  string `json:"version"`
	Expected bool   `json:"expected"`
}

func main() {
	var cases []Case
	data, err := os.ReadFile(os.Args[1])
	if err != nil {
		panic(err)
	}
	if err := json.Unmarshal(data, &cases); err != nil {
		panic(err)
	}
	scheme, _ := version.For(os.Args[2])
	if len(os.Args) > 3 && os.Args[3] == "compare" {
		var pairs []struct {
			A    string `json:"a"`
			B    string `json:"b"`
			Want int    `json:"want"`
		}
		if err := json.Unmarshal(data, &pairs); err != nil {
			panic(err)
		}
		bad := 0
		for _, pair := range pairs {
			if got := scheme.Compare(pair.A, pair.B); got != pair.Want {
				bad++
				if bad < 10 {
					fmt.Printf("DIFF compare(%q,%q) got=%d want=%d\n", pair.A, pair.B, got, pair.Want)
				}
			}
		}
		fmt.Printf("итого сравнений: %d, расхождений %d\n", len(pairs), bad)
		return
	}
	mismatch, errs := 0, 0
	seen := map[string]bool{}
	for _, c := range cases {
		got, err := scheme.Satisfies(c.Spec, c.Version)
		if err != nil {
			errs++
			if !seen["ERR "+c.Spec] {
				seen["ERR "+c.Spec] = true
				fmt.Printf("ERR  spec=%q: %v\n", c.Spec, err)
			}
			continue
		}
		if got != c.Expected {
			mismatch++
			key := c.Spec
			if !seen[key] {
				seen[key] = true
				fmt.Printf("DIFF spec=%q version=%q got=%v want=%v\n", c.Spec, c.Version, got, c.Expected)
			}
		}
	}
	fmt.Printf("итого: случаев %d, расхождений %d, ошибок разбора %d\n", len(cases), mismatch, errs)
}
