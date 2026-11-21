package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"filippo.io/age"
)

// env is a sandbox with a built veil binary and two users: alice (in group core) and bob (not).
type env struct {
	t                *testing.T
	dir, bin         string
	aliceKey, bobKey string
	alicePub, bobPub string
}

func newEnv(t *testing.T) *env {
	t.Helper()
	dir := t.TempDir()
	bin := filepath.Join(dir, "bin")
	build := exec.Command("go", "build", "-o", filepath.Join(bin, "veil"), ".")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build: %v\n%s", err, out)
	}
	e := &env{t: t, dir: dir, bin: bin}
	e.aliceKey, e.alicePub = writeIdentity(t, filepath.Join(dir, "alice.key"))
	e.bobKey, e.bobPub = writeIdentity(t, filepath.Join(dir, "bob.key"))
	return e
}

func writeIdentity(t *testing.T, path string) (string, string) {
	id, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(id.String()+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return path, id.Recipient().String()
}

// run executes a shell command in dir as the user owning key.
func (e *env) run(key, dir, script string) (string, error) {
	cmd := exec.Command("sh", "-c", script)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(),
		"PATH="+e.bin+string(os.PathListSeparator)+os.Getenv("PATH"),
		"HOME="+e.dir, "VEIL_IDENTITY="+key,
		"GIT_CONFIG_GLOBAL=/dev/null", "GIT_CONFIG_NOSYSTEM=1",
		"GIT_AUTHOR_NAME=t", "GIT_AUTHOR_EMAIL=t@t", "GIT_COMMITTER_NAME=t", "GIT_COMMITTER_EMAIL=t@t",
	)
	out, err := cmd.CombinedOutput()
	return string(out), err
}

func (e *env) must(key, dir, script string) string {
	e.t.Helper()
	out, err := e.run(key, dir, script)
	if err != nil {
		e.t.Fatalf("%s: %v\n%s", script, err, out)
	}
	return out
}

func TestEndToEnd(t *testing.T) {
	e := newEnv(t)
	origin := filepath.Join(e.dir, "origin.git")
	alice := filepath.Join(e.dir, "alice")
	e.must(e.aliceKey, e.dir, "git init -q --bare -b main origin.git && git init -q -b main alice")

	policy := `members:
  alice: ` + e.alicePub + `
  bob: ` + e.bobPub + `
groups:
  core: [alice]
  everyone: [alice, bob]
files:
  - match: "private/**"
    groups: [core]
  - match: "*.pem"
    groups: [core]
branches:
  - match: "private/*"
    groups: [core]
secrets:
  - match: "PROD_*"
    groups: [core]
  - match: "*"
    groups: [everyone]
`
	os.MkdirAll(filepath.Join(alice, ".veil"), 0o755)
	os.WriteFile(filepath.Join(alice, ".veil", "policy.yaml"), []byte(policy), 0o644)
	os.MkdirAll(filepath.Join(alice, "private"), 0o755)
	os.WriteFile(filepath.Join(alice, "private", "plan.md"), []byte("acquire competitor\n"), 0o644)
	os.WriteFile(filepath.Join(alice, "README.md"), []byte("public\n"), 0o644)
	os.MkdirAll(filepath.Join(alice, "deploy"), 0o755)
	os.WriteFile(filepath.Join(alice, "deploy", "server.pem"), []byte("KEY\n"), 0o644)

	e.must(e.aliceKey, alice, "veil install && veil sync && git add -A && git commit -qm init && git remote add origin "+origin)

	// Private files are stored encrypted; public ones are not.
	for _, f := range []string{"private/plan.md", "deploy/server.pem"} {
		blob := e.must(e.aliceKey, alice, "git cat-file blob HEAD:"+f)
		if !strings.HasPrefix(blob, "# veil:v1") || strings.Contains(blob, "acquire") {
			t.Fatalf("%s not encrypted in HEAD:\n%s", f, blob)
		}
	}
	if got := e.must(e.aliceKey, alice, "git cat-file blob HEAD:README.md"); got != "public\n" {
		t.Fatalf("README changed: %q", got)
	}
	// Re-cleaning must be stable (no phantom modifications).
	if st := e.must(e.aliceKey, alice, "touch private/plan.md && git status --porcelain"); st != "" {
		t.Fatalf("unexpected status after touch: %q", st)
	}
	// Editing produces a readable diff for alice.
	os.WriteFile(filepath.Join(alice, "private", "plan.md"), []byte("acquire competitor\nfriday\n"), 0o644)
	if d := e.must(e.aliceKey, alice, "git diff"); !strings.Contains(d, "+friday") {
		t.Fatalf("diff not decrypted:\n%s", d)
	}
	e.must(e.aliceKey, alice, "git commit -qam edit")

	// Secrets.
	e.must(e.aliceKey, alice, "veil secret set PROD_DB postgres://prod && veil secret set API_URL https://api && git add -A && git commit -qm secrets")
	if got := e.must(e.aliceKey, alice, "veil run -- sh -c 'echo $PROD_DB $API_URL'"); got != "postgres://prod https://api\n" {
		t.Fatalf("veil run: %q", got)
	}

	// Private branch: plain push is blocked, veil branch push works.
	e.must(e.aliceKey, alice, "git push -q origin main && git checkout -qb private/exp && echo idea > idea.txt && git add idea.txt && git commit -qm idea")
	if out, err := e.run(e.aliceKey, alice, "git push origin private/exp"); err == nil || !strings.Contains(out, "private branch") {
		t.Fatalf("plain push of private branch was not blocked: %v\n%s", err, out)
	}
	e.must(e.aliceKey, alice, "veil branch push private/exp --remote origin")
	if heads := e.must(e.aliceKey, alice, "git ls-remote origin refs/heads/*"); strings.Contains(heads, "private") {
		t.Fatalf("private branch leaked as a head: %s", heads)
	}

	// A second alice clone can read everything.
	e.must(e.aliceKey, e.dir, "git clone -q "+origin+" alice2")
	alice2 := filepath.Join(e.dir, "alice2")
	e.must(e.aliceKey, alice2, "veil install && veil unlock")
	if b, _ := os.ReadFile(filepath.Join(alice2, "private", "plan.md")); string(b) != "acquire competitor\nfriday\n" {
		t.Fatalf("alice2 plan.md: %q", b)
	}
	if st := e.must(e.aliceKey, alice2, "git status --porcelain"); st != "" {
		t.Fatalf("alice2 dirty after unlock: %q", st)
	}
	e.must(e.aliceKey, alice2, "veil branch pull private/exp --remote origin")
	if got := e.must(e.aliceKey, alice2, "git show private/exp:idea.txt"); got != "idea\n" {
		t.Fatalf("pulled branch: %q", got)
	}

	// Bob sees ciphertext, can read only the shared secret, and cannot pull the branch.
	e.must(e.bobKey, e.dir, "git clone -q "+origin+" bob")
	bob := filepath.Join(e.dir, "bob")
	out := e.must(e.bobKey, bob, "veil install && veil unlock")
	if !strings.Contains(out, "locked    private/plan.md") {
		t.Fatalf("bob unlock output: %s", out)
	}
	if b, _ := os.ReadFile(filepath.Join(bob, "private", "plan.md")); strings.Contains(string(b), "acquire") {
		t.Fatal("bob can read private file")
	}
	if st := e.must(e.bobKey, bob, "git status --porcelain"); st != "" {
		t.Fatalf("bob dirty: %q", st)
	}
	if got := e.must(e.bobKey, bob, "veil secret get API_URL"); got != "https://api" {
		t.Fatalf("bob API_URL: %q", got)
	}
	if _, err := e.run(e.bobKey, bob, "veil secret get PROD_DB"); err == nil {
		t.Fatal("bob read PROD_DB")
	}
	if out, err := e.run(e.bobKey, bob, "veil branch pull private/exp --remote origin"); err == nil {
		t.Fatalf("bob pulled private branch:\n%s", out)
	}
	// Bob can still commit public changes without touching private files.
	e.must(e.bobKey, bob, "echo more >> README.md && git commit -qam readme && git push -q origin main")

	// Granting bob access: alice updates the policy and rekeys; bob can then read.
	e.must(e.aliceKey, alice, "git checkout -q main && git pull -q --rebase origin main")
	b, _ := os.ReadFile(filepath.Join(alice, ".veil", "policy.yaml"))
	os.WriteFile(filepath.Join(alice, ".veil", "policy.yaml"), []byte(strings.Replace(string(b), "core: [alice]", "core: [alice, bob]", 1)), 0o644)
	e.must(e.aliceKey, alice, "veil rekey && git add -A && git commit -qm 'grant bob' && git push -q origin main")
	e.must(e.bobKey, bob, "git pull -q origin main && veil unlock")
	if b, _ := os.ReadFile(filepath.Join(bob, "private", "plan.md")); string(b) != "acquire competitor\nfriday\n" {
		t.Fatalf("bob after grant: %q", b)
	}
	if got := e.must(e.bobKey, bob, "veil secret get PROD_DB"); got != "postgres://prod" {
		t.Fatalf("bob PROD_DB after grant: %q", got)
	}
}
