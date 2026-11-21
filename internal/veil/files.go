package veil

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// Clean is the git clean filter: it turns plaintext from the working tree into ciphertext for the index.
func Clean(file string, in []byte) ([]byte, error) {
	if IsSealed(in) {
		return in, nil // already encrypted, e.g. a checkout by someone without access
	}
	_, pol, err := loadRepoPolicy()
	if err != nil {
		return nil, fmt.Errorf("veil: refusing to commit %s unencrypted: %w", file, err)
	}
	rule := pol.FileRule(file)
	if rule == nil {
		return nil, fmt.Errorf("veil: %s has filter=veil but matches no policy rule; run `veil sync`", file)
	}
	recips, hash, err := pol.Recipients(rule)
	if err != nil {
		return nil, err
	}
	// age encryption is randomized, so reuse the existing ciphertext when nothing changed.
	// Otherwise every `git status` would see a modified file.
	ids := ageIdentities()
	for _, ref := range []string{":" + file, "HEAD:" + file} {
		old, err := gitRaw(nil, nil, "cat-file", "blob", ref)
		if err != nil || !IsSealed(old) {
			continue
		}
		if _, h := Meta(old); h != hash {
			continue
		}
		if pt, err := Open(old, ids); err == nil && bytes.Equal(pt, in) {
			return old, nil
		}
	}
	return Seal(in, recips, rule.Groups, hash)
}

// Smudge is the git smudge filter: it decrypts on checkout when we can and leaves ciphertext otherwise.
func Smudge(in []byte) []byte {
	if !IsSealed(in) {
		return in
	}
	pt, err := Open(in, ageIdentities())
	if err != nil {
		return in
	}
	return pt
}

func Textconv(file string, w io.Writer) error {
	data, err := os.ReadFile(file)
	if err != nil {
		return err
	}
	_, err = w.Write(Smudge(data))
	return err
}

// ManagedFiles lists tracked files covered by a policy file rule.
func ManagedFiles(root string, pol *Policy) ([]string, error) {
	out, err := gitRaw(nil, nil, "-C", root, "ls-files", "-z")
	if err != nil {
		return nil, err
	}
	var files []string
	for _, f := range strings.Split(string(out), "\x00") {
		if f != "" && pol.FileRule(f) != nil {
			files = append(files, f)
		}
	}
	return files, nil
}

// Unlock decrypts managed files in the working tree that we have access to.
func Unlock(w io.Writer) error {
	root, pol, err := loadRepoPolicy()
	if err != nil {
		return err
	}
	files, err := ManagedFiles(root, pol)
	if err != nil {
		return err
	}
	ids := ageIdentities()
	var readable []string
	for _, f := range files {
		data, err := os.ReadFile(filepath.Join(root, f))
		if err != nil || !IsSealed(data) {
			continue
		}
		if _, err := Open(data, ids); errors.Is(err, ErrNoAccess) {
			fmt.Fprintf(w, "locked    %s (no access)\n", f)
			continue
		} else if err != nil {
			return fmt.Errorf("%s: %w", f, err)
		}
		readable = append(readable, f)
	}
	if len(readable) == 0 {
		return nil
	}
	// Re-checkout through the smudge filter (rather than writing files directly) so git's
	// cached stat data matches; otherwise `git status` reports the files as modified.
	for _, f := range readable {
		if err := os.Remove(filepath.Join(root, f)); err != nil {
			return err
		}
	}
	if _, err := git(append([]string{"-C", root, "checkout", "--"}, readable...)...); err != nil {
		return err
	}
	for _, f := range readable {
		fmt.Fprintf(w, "unlocked  %s\n", f)
	}
	return nil
}

// Status reports, for each managed file, whether HEAD stores it encrypted and whether we can read it.
func Status(w io.Writer) error {
	root, pol, err := loadRepoPolicy()
	if err != nil {
		return err
	}
	files, err := ManagedFiles(root, pol)
	if err != nil {
		return err
	}
	ids := ageIdentities()
	leaks := 0
	for _, f := range files {
		blob, err := gitRaw(nil, nil, "-C", root, "cat-file", "blob", ":"+f)
		if err != nil {
			continue
		}
		state := "readable"
		if !IsSealed(blob) {
			state, leaks = "PLAINTEXT IN INDEX", leaks+1
		} else if _, err := Open(blob, ids); err != nil {
			state = "locked"
		}
		fmt.Fprintf(w, "%-20s %-30s groups=%s\n", state, f, strings.Join(pol.FileRule(f).Groups, ","))
	}
	if leaks > 0 {
		return fmt.Errorf("%d private file(s) are staged as plaintext; run `veil install && veil rekey`", leaks)
	}
	return nil
}

// Rekey re-encrypts managed files and secrets for the current policy (after membership changes).
func Rekey(w io.Writer) error {
	root, pol, err := loadRepoPolicy()
	if err != nil {
		return err
	}
	files, err := ManagedFiles(root, pol)
	if err != nil {
		return err
	}
	// Clean passes ciphertext through untouched, so decrypt readable files first.
	if err := Unlock(w); err != nil {
		return err
	}
	if len(files) > 0 {
		args := append([]string{"-C", root, "add", "--renormalize", "--"}, files...)
		if _, err := git(args...); err != nil {
			return err
		}
	}
	if err := rekeySecrets(root, pol, w); err != nil {
		return err
	}
	fmt.Fprintln(w, "Re-encrypted what you can read. Review with `git status` and commit.")
	return nil
}
