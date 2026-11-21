package veil

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

const branchRefPrefix = "refs/veil/branches/"

// Commits made by veil itself use a fixed identity so they don't leak who pushed.
var veilCommitEnv = []string{
	"GIT_AUTHOR_NAME=veil", "GIT_AUTHOR_EMAIL=veil@localhost",
	"GIT_COMMITTER_NAME=veil", "GIT_COMMITTER_EMAIL=veil@localhost",
}

// BranchPush encrypts a private branch into a git bundle and stores it under refs/veil/branches/<name>.
// Commits reachable from base (e.g. main) are excluded since everyone already has them.
func BranchPush(branch, remote, base string, w io.Writer) error {
	_, pol, err := loadRepoPolicy()
	if err != nil {
		return err
	}
	rule := pol.BranchRule(branch)
	if rule == nil {
		return fmt.Errorf("branch %q is not private: no branches rule in %s matches it", branch, PolicyPath)
	}
	recips, hash, err := pol.Recipients(rule)
	if err != nil {
		return err
	}
	tmp, err := os.MkdirTemp("", "veil-bundle")
	if err != nil {
		return err
	}
	defer os.RemoveAll(tmp)
	bundle := filepath.Join(tmp, "branch.bundle")
	args := []string{"bundle", "create", bundle, "refs/heads/" + branch}
	if base != "" {
		if _, err := git("rev-parse", "--verify", "--quiet", base); err == nil {
			args = append(args, "^"+base)
		}
	}
	if _, err := git(args...); err != nil {
		return err
	}
	data, err := os.ReadFile(bundle)
	if err != nil {
		return err
	}
	sealed, err := Seal(data, recips, rule.Groups, hash)
	if err != nil {
		return err
	}
	blob, err := gitRaw(sealed, nil, "hash-object", "-w", "--stdin")
	if err != nil {
		return err
	}
	tree, err := gitRaw([]byte(fmt.Sprintf("100644 blob %s\tbundle.age\n", strings.TrimSpace(string(blob)))), nil, "mktree")
	if err != nil {
		return err
	}
	commit, err := gitRaw(nil, veilCommitEnv, "commit-tree", strings.TrimSpace(string(tree)), "-m", "veil: encrypted branch "+branch)
	if err != nil {
		return err
	}
	ref := branchRefPrefix + branch
	if _, err := git("update-ref", ref, strings.TrimSpace(string(commit))); err != nil {
		return err
	}
	fmt.Fprintf(w, "sealed %s for groups %s\n", branch, strings.Join(rule.Groups, ","))
	if remote == "" {
		return nil
	}
	// Lease against the last value seen on this remote, so a stale clone can't silently
	// overwrite a teammate's newer push. Empty means the ref must not exist yet.
	track := trackingRef(remote, branch)
	seen, _ := git("rev-parse", "--verify", "--quiet", track)
	if _, err := git("push", "--no-verify", "--force-with-lease="+ref+":"+seen, remote, ref+":"+ref); err != nil {
		return fmt.Errorf("%w\nthe remote has a newer version; run `veil branch pull %s --remote %s` first", err, branch, remote)
	}
	if _, err := git("update-ref", track, ref); err != nil {
		return err
	}
	fmt.Fprintf(w, "pushed %s to %s\n", ref, remote)
	return nil
}

func trackingRef(remote, branch string) string { return "refs/veil/remotes/" + remote + "/" + branch }

// BranchPull fetches and decrypts a private branch into refs/heads/<name>.
func BranchPull(branch, remote string, w io.Writer) error {
	ref := branchRefPrefix + branch
	if remote != "" {
		track := trackingRef(remote, branch)
		if _, err := git("fetch", remote, "+"+ref+":"+track); err != nil {
			return err
		}
		if _, err := git("update-ref", ref, track); err != nil {
			return err
		}
	}
	sealed, err := gitRaw(nil, nil, "cat-file", "blob", ref+":bundle.age")
	if err != nil {
		return fmt.Errorf("no encrypted branch %q found locally (pass --remote to fetch it)", branch)
	}
	data, err := Open(sealed, ageIdentities())
	if err != nil {
		return fmt.Errorf("branch %q: %w", branch, err)
	}
	tmp, err := os.MkdirTemp("", "veil-bundle")
	if err != nil {
		return err
	}
	defer os.RemoveAll(tmp)
	bundle := filepath.Join(tmp, "branch.bundle")
	if err := os.WriteFile(bundle, data, 0o600); err != nil {
		return err
	}
	// Fast-forward only, so unpushed local commits are never discarded.
	if current, _ := git("symbolic-ref", "--quiet", "--short", "HEAD"); current == branch {
		if _, err := git("fetch", bundle, "refs/heads/"+branch); err != nil {
			return err
		}
		if _, err := git("merge", "--ff-only", "FETCH_HEAD"); err != nil {
			return err
		}
	} else if _, err := git("fetch", bundle, "refs/heads/"+branch+":refs/heads/"+branch); err != nil {
		return err
	}
	fmt.Fprintf(w, "updated branch %s\n", branch)
	return nil
}

func BranchList(remote string, w io.Writer) error {
	var out string
	var err error
	if remote != "" {
		out, err = git("ls-remote", remote, branchRefPrefix+"*")
	} else {
		out, err = git("for-each-ref", "--format=%(objectname) %(refname)", branchRefPrefix)
	}
	if err != nil {
		return err
	}
	for _, line := range strings.Split(out, "\n") {
		f := strings.Fields(line)
		if len(f) == 2 {
			fmt.Fprintln(w, strings.TrimPrefix(f[1], branchRefPrefix))
		}
	}
	return nil
}
