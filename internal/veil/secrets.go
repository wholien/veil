package veil

import (
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

const secretsDir = ".veil/secrets"

var secretName = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

func secretPath(root, name string) string { return filepath.Join(root, secretsDir, name+".age") }

func SecretSet(name string, value []byte) error {
	if !secretName.MatchString(name) {
		return fmt.Errorf("invalid secret name %q (use letters, digits and _)", name)
	}
	root, pol, err := loadRepoPolicy()
	if err != nil {
		return err
	}
	return writeSecret(root, pol, name, value)
}

func writeSecret(root string, pol *Policy, name string, value []byte) error {
	rule := pol.SecretRule(name)
	if rule == nil {
		return fmt.Errorf("no secrets rule in %s matches %q", PolicyPath, name)
	}
	recips, hash, err := pol.Recipients(rule)
	if err != nil {
		return err
	}
	sealed, err := Seal(value, recips, rule.Groups, hash)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Join(root, secretsDir), 0o755); err != nil {
		return err
	}
	return os.WriteFile(secretPath(root, name), sealed, 0o644)
}

func SecretGet(name string) ([]byte, error) {
	root, err := RepoRoot()
	if err != nil {
		return nil, err
	}
	data, err := os.ReadFile(secretPath(root, name))
	if err != nil {
		return nil, fmt.Errorf("secret %q not found", name)
	}
	return Open(data, ageIdentities())
}

func SecretRemove(name string) error {
	root, err := RepoRoot()
	if err != nil {
		return err
	}
	return os.Remove(secretPath(root, name))
}

func secretNames(root string) []string {
	entries, _ := os.ReadDir(filepath.Join(root, secretsDir))
	var names []string
	for _, e := range entries {
		if n, ok := strings.CutSuffix(e.Name(), ".age"); ok {
			names = append(names, n)
		}
	}
	sort.Strings(names)
	return names
}

func SecretList(w io.Writer) error {
	root, err := RepoRoot()
	if err != nil {
		return err
	}
	ids := ageIdentities()
	for _, n := range secretNames(root) {
		data, err := os.ReadFile(secretPath(root, n))
		if err != nil {
			return err
		}
		groups, _ := Meta(data)
		state := "readable"
		if _, err := Open(data, ids); err != nil {
			state = "locked"
		}
		fmt.Fprintf(w, "%-9s %-30s groups=%s\n", state, n, strings.Join(groups, ","))
	}
	return nil
}

// Run executes a command with every secret we can read injected as an environment variable.
func Run(args []string) (int, error) {
	if len(args) == 0 {
		return 2, errors.New("usage: veil run -- <command> [args...]")
	}
	root, err := RepoRoot()
	if err != nil {
		return 1, err
	}
	env := os.Environ()
	ids := ageIdentities()
	for _, n := range secretNames(root) {
		data, err := os.ReadFile(secretPath(root, n))
		if err != nil {
			return 1, err
		}
		if v, err := Open(data, ids); err == nil {
			env = append(env, n+"="+string(v))
		}
	}
	cmd := exec.Command(args[0], args[1:]...)
	cmd.Env, cmd.Stdin, cmd.Stdout, cmd.Stderr = env, os.Stdin, os.Stdout, os.Stderr
	if err := cmd.Run(); err != nil {
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			return ee.ExitCode(), nil
		}
		return 1, err
	}
	return 0, nil
}

func rekeySecrets(root string, pol *Policy, w io.Writer) error {
	ids := ageIdentities()
	for _, n := range secretNames(root) {
		data, err := os.ReadFile(secretPath(root, n))
		if err != nil {
			return err
		}
		v, err := Open(data, ids)
		if err != nil {
			fmt.Fprintf(w, "skipped secret %s (no access)\n", n)
			continue
		}
		if err := writeSecret(root, pol, n, v); err != nil {
			return err
		}
	}
	return nil
}
