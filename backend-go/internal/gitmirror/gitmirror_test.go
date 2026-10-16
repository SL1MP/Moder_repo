package gitmirror

import "testing"

func TestTargetPath(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"https://example.com/group/project.git", "example.com/group/project"},
		{"http://git.example.test/a/b/project/", "git.example.test/a/b/project"},
	}
	for _, test := range tests {
		got, err := TargetPath(test.input)
		if err != nil {
			t.Fatalf("TargetPath(%q): %v", test.input, err)
		}
		if got != test.want {
			t.Errorf("TargetPath(%q) = %q, want %q", test.input, got, test.want)
		}
	}
}

func TestTargetPathRejectsCredentialsAndIncompletePath(t *testing.T) {
	for _, input := range []string{
		"https://user:secret@example.com/group/project",
		"https://example.com/project",
		"file:///tmp/project",
	} {
		if _, err := TargetPath(input); err == nil {
			t.Errorf("TargetPath(%q) accepted unsafe URL", input)
		}
	}
}
