package veil

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"

	"filippo.io/age"
	"filippo.io/age/agessh"
	"github.com/bmatcuk/doublestar/v4"
	"gopkg.in/yaml.v3"
)

const PolicyPath = ".veil/policy.yaml"

// Policy declares who can read which files, branches and secrets.
type Policy struct {
	Members  map[string]string   `yaml:"members"`
	Groups   map[string][]string `yaml:"groups"`
	Files    []Rule              `yaml:"files"`
	Branches []Rule              `yaml:"branches"`
	Secrets  []Rule              `yaml:"secrets"`
}

// Rule grants the listed groups access to everything matching Match.
// The first matching rule wins.
type Rule struct {
	Match  string   `yaml:"match"`
	Groups []string `yaml:"groups"`
}

func LoadPolicy(root string) (*Policy, error) {
	data, err := os.ReadFile(filepath.Join(root, PolicyPath))
	if err != nil {
		return nil, err
	}
	var p Policy
	if err := yaml.Unmarshal(data, &p); err != nil {
		return nil, fmt.Errorf("parse %s: %w", PolicyPath, err)
	}
	return &p, p.validate()
}

func (p *Policy) validate() error {
	for name, key := range p.Members {
		if _, err := parseRecipient(key); err != nil {
			return fmt.Errorf("member %q: %w", name, err)
		}
	}
	for g, members := range p.Groups {
		for _, m := range members {
			if _, ok := p.Members[m]; !ok {
				return fmt.Errorf("group %q references unknown member %q", g, m)
			}
		}
	}
	for _, rules := range [][]Rule{p.Files, p.Branches, p.Secrets} {
		for _, r := range rules {
			if !doublestar.ValidatePattern(strings.TrimPrefix(r.Match, "/")) {
				return fmt.Errorf("invalid pattern %q", r.Match)
			}
			for _, g := range r.Groups {
				if _, ok := p.Groups[g]; !ok {
					return fmt.Errorf("rule %q references unknown group %q", r.Match, g)
				}
			}
		}
	}
	return nil
}

func firstMatch(rules []Rule, name string, basenameIfNoSlash bool) *Rule {
	for i := range rules {
		pat := strings.TrimPrefix(rules[i].Match, "/")
		target := name
		// Mirror .gitattributes semantics: a pattern without a slash matches the basename anywhere.
		if basenameIfNoSlash && !strings.Contains(rules[i].Match, "/") {
			target = path.Base(name)
		}
		if ok, _ := doublestar.Match(pat, target); ok {
			return &rules[i]
		}
	}
	return nil
}

func (p *Policy) FileRule(file string) *Rule {
	return firstMatch(p.Files, filepath.ToSlash(file), true)
}
func (p *Policy) BranchRule(name string) *Rule { return firstMatch(p.Branches, name, false) }
func (p *Policy) SecretRule(name string) *Rule { return firstMatch(p.Secrets, name, false) }

// Keys returns the sorted, de-duplicated public keys of everyone the rule grants access to.
func (p *Policy) Keys(r *Rule) []string {
	set := map[string]bool{}
	for _, g := range r.Groups {
		for _, m := range p.Groups[g] {
			set[p.Members[m]] = true
		}
	}
	keys := make([]string, 0, len(set))
	for k := range set {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// Recipients returns age recipients for the rule plus a short hash identifying that recipient set.
func (p *Policy) Recipients(r *Rule) ([]age.Recipient, string, error) {
	keys := p.Keys(r)
	if len(keys) == 0 {
		return nil, "", fmt.Errorf("rule %q grants access to nobody", r.Match)
	}
	var out []age.Recipient
	for _, k := range keys {
		rc, err := parseRecipient(k)
		if err != nil {
			return nil, "", err
		}
		out = append(out, rc)
	}
	sum := sha256.Sum256([]byte(strings.Join(keys, "\n")))
	return out, hex.EncodeToString(sum[:])[:16], nil
}

// GroupsFor lists the groups that contain a member with the given public key.
func (p *Policy) GroupsFor(pub string) []string {
	var out []string
	for g, members := range p.Groups {
		for _, m := range members {
			if sameKey(p.Members[m], pub) {
				out = append(out, g)
				break
			}
		}
	}
	sort.Strings(out)
	return out
}

func sameKey(a, b string) bool {
	fa, fb := strings.Fields(a), strings.Fields(b)
	if len(fa) == 0 || len(fb) == 0 {
		return false
	}
	if len(fa) >= 2 && len(fb) >= 2 {
		return fa[0] == fb[0] && fa[1] == fb[1]
	}
	return fa[0] == fb[0]
}

func parseRecipient(key string) (age.Recipient, error) {
	key = strings.TrimSpace(key)
	if strings.HasPrefix(key, "age1") {
		return age.ParseX25519Recipient(key)
	}
	if strings.HasPrefix(key, "ssh-") {
		return agessh.ParseRecipient(key)
	}
	return nil, fmt.Errorf("unsupported key %q (want age1... or ssh-...)", key)
}
