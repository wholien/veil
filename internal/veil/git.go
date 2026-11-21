package veil

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"strings"
)

func gitRaw(stdin []byte, env []string, args ...string) ([]byte, error) {
	cmd := exec.Command("git", args...)
	if stdin != nil {
		cmd.Stdin = bytes.NewReader(stdin)
	}
	if env != nil {
		cmd.Env = append(os.Environ(), env...)
	}
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		return out, fmt.Errorf("git %s: %v: %s", strings.Join(args, " "), err, strings.TrimSpace(stderr.String()))
	}
	return out, nil
}

func git(args ...string) (string, error) {
	out, err := gitRaw(nil, nil, args...)
	return strings.TrimSpace(string(out)), err
}

func RepoRoot() (string, error) { return git("rev-parse", "--show-toplevel") }

func loadRepoPolicy() (string, *Policy, error) {
	root, err := RepoRoot()
	if err != nil {
		return "", nil, err
	}
	p, err := LoadPolicy(root)
	return root, p, err
}
