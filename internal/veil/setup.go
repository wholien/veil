package veil

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

const (
	attrBegin = "# BEGIN veil (generated from .veil/policy.yaml by `veil sync`; do not edit)"
	attrEnd   = "# END veil"
	hookBody  = "#!/bin/sh\n# installed by veil\nexec veil hook pre-push \"$@\"\n"
)

// Install configures the git filter, diff driver and pre-push hook for this clone.
func Install(w io.Writer) error {
	cfg := [][2]string{
		{"filter.veil.clean", "veil clean %f"},
		{"filter.veil.smudge", "veil smudge %f"},
		{"filter.veil.required", "true"},
		{"diff.veil.textconv", "veil textconv"},
	}
	for _, kv := range cfg {
		if _, err := git("config", kv[0], kv[1]); err != nil {
			return err
		}
	}
	hook, err := git("rev-parse", "--git-path", "hooks/pre-push")
	if err != nil {
		return err
	}
	if existing, err := os.ReadFile(hook); err == nil && !strings.Contains(string(existing), "installed by veil") {
		fmt.Fprintf(w, "warning: %s exists; add `veil hook pre-push \"$@\"` to it to block plaintext pushes of private branches\n", hook)
	} else {
		if err := os.MkdirAll(filepath.Dir(hook), 0o755); err != nil {
			return err
		}
		if err := os.WriteFile(hook, []byte(hookBody), 0o755); err != nil {
			return err
		}
	}
	fmt.Fprintln(w, "installed git filter, diff driver and pre-push hook")
	return nil
}

// Sync regenerates the veil block in .gitattributes from the policy's file rules.
func Sync(w io.Writer) error {
	root, pol, err := loadRepoPolicy()
	if err != nil {
		return err
	}
	path := filepath.Join(root, ".gitattributes")
	existing, _ := os.ReadFile(path)
	var kept []string
	inBlock := false
	for _, line := range strings.Split(strings.TrimRight(string(existing), "\n"), "\n") {
		switch {
		case line == attrBegin:
			inBlock = true
		case line == attrEnd:
			inBlock = false
		case !inBlock && line != "":
			kept = append(kept, line)
		}
	}
	block := []string{attrBegin}
	for _, r := range pol.Files {
		block = append(block, r.Match+" filter=veil diff=veil")
	}
	block = append(block, attrEnd)
	out := strings.Join(append(kept, block...), "\n") + "\n"
	if err := os.WriteFile(path, []byte(out), 0o644); err != nil {
		return err
	}
	fmt.Fprintf(w, "wrote %d rule(s) to .gitattributes\n", len(pol.Files))
	return nil
}

// Init creates a starter policy (granting yourself access), then installs and syncs.
func Init(w io.Writer) error {
	root, err := RepoRoot()
	if err != nil {
		return err
	}
	policyFile := filepath.Join(root, PolicyPath)
	if _, err := os.Stat(policyFile); errors.Is(err, os.ErrNotExist) {
		pub, err := myPublicKey(w)
		if err != nil {
			return err
		}
		if err := os.MkdirAll(filepath.Dir(policyFile), 0o755); err != nil {
			return err
		}
		if err := os.WriteFile(policyFile, []byte(fmt.Sprintf(starterPolicy, pub)), 0o644); err != nil {
			return err
		}
		fmt.Fprintf(w, "created %s\n", PolicyPath)
	}
	if err := Install(w); err != nil {
		return err
	}
	return Sync(w)
}

func myPublicKey(w io.Writer) (string, error) {
	for _, id := range LoadIdentities() {
		if id.Public != "" {
			return id.Public, nil
		}
	}
	path := DefaultIdentityPath()
	pub, err := Keygen(path)
	if err != nil {
		return "", err
	}
	fmt.Fprintf(w, "generated identity %s\n", path)
	return pub, nil
}

// Whoami prints your public keys and the groups they belong to.
func Whoami(w io.Writer) error {
	ids := LoadIdentities()
	if len(ids) == 0 {
		return errors.New("no identity found; run `veil keygen`")
	}
	_, pol, _ := loadRepoPolicy()
	for _, id := range ids {
		groups := "-"
		if pol != nil && id.Public != "" {
			if g := pol.GroupsFor(id.Public); len(g) > 0 {
				groups = strings.Join(g, ",")
			}
		}
		fmt.Fprintf(w, "%s\n  key:    %s\n  groups: %s\n", id.Path, id.Public, groups)
	}
	return nil
}

// HookPrePush rejects pushing private branches as normal refs. Input is git's pre-push stdin.
func HookPrePush(in io.Reader) error {
	_, pol, err := loadRepoPolicy()
	if err != nil {
		return nil
	}
	for _, line := range readLines(in) {
		f := strings.Fields(line)
		if len(f) != 4 || strings.Trim(f[1], "0") == "" {
			continue
		}
		if name, ok := strings.CutPrefix(f[2], "refs/heads/"); ok && pol.BranchRule(name) != nil {
			return fmt.Errorf("veil: %q is a private branch; push it with `veil branch push %s --remote <remote>`", name, name)
		}
	}
	return nil
}

const starterPolicy = `# veil policy: who can read what. Commit this file.
# Members are age public keys (age1...) or SSH public keys (ssh-ed25519 ...).
members:
  me: %s

groups:
  core: [me]

# Files matching these patterns are encrypted on commit. First match wins.
# Patterns follow .gitattributes rules; run "veil sync" after editing.
files:
  - match: "private/**"
    groups: [core]

# Branches matching these patterns can only be shared with "veil branch push".
branches:
  - match: "private/*"
    groups: [core]

# Secrets set with "veil secret set NAME". First match wins.
secrets:
  - match: "*"
    groups: [core]
`
