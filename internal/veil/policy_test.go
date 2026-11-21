package veil

import "testing"

func TestFileRuleMatching(t *testing.T) {
	p := &Policy{Files: []Rule{
		{Match: "*.pem", Groups: []string{"a"}},
		{Match: "/private/**", Groups: []string{"b"}},
		{Match: "docs/internal/*.md", Groups: []string{"c"}},
	}}
	cases := map[string]string{
		"key.pem":                "*.pem",
		"deploy/sub/key.pem":     "*.pem",
		"private/x/y.txt":        "/private/**",
		"docs/internal/a.md":     "docs/internal/*.md",
		"docs/internal/sub/a.md": "",
		"src/private/x":          "",
		"README.md":              "",
	}
	for file, want := range cases {
		got := ""
		if r := p.FileRule(file); r != nil {
			got = r.Match
		}
		if got != want {
			t.Errorf("FileRule(%q) = %q, want %q", file, got, want)
		}
	}
}

func TestPolicyValidation(t *testing.T) {
	p := &Policy{
		Members: map[string]string{"a": "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p"},
		Groups:  map[string][]string{"g": {"a", "ghost"}},
	}
	if err := p.validate(); err == nil {
		t.Fatal("expected error for unknown member")
	}
}
