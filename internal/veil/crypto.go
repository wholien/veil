package veil

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"filippo.io/age"
	"filippo.io/age/agessh"
	"filippo.io/age/armor"
)

const magic = "# veil:v1"

// Seal encrypts plaintext to recipients and wraps it in a small readable header.
func Seal(plaintext []byte, recips []age.Recipient, groups []string, hash string) ([]byte, error) {
	var buf bytes.Buffer
	fmt.Fprintf(&buf, "%s groups=%s recipients=%s\n", magic, strings.Join(groups, ","), hash)
	buf.WriteString("# Encrypted with veil. Only members of the groups above can read it.\n")
	aw := armor.NewWriter(&buf)
	w, err := age.Encrypt(aw, recips...)
	if err != nil {
		return nil, err
	}
	if _, err := w.Write(plaintext); err != nil {
		return nil, err
	}
	if err := w.Close(); err != nil {
		return nil, err
	}
	if err := aw.Close(); err != nil {
		return nil, err
	}
	buf.WriteByte('\n')
	return buf.Bytes(), nil
}

func IsSealed(b []byte) bool { return bytes.HasPrefix(b, []byte(magic)) }

// Meta returns the groups and recipient hash recorded in a sealed blob's header.
func Meta(b []byte) (groups []string, hash string) {
	line, _, _ := bytes.Cut(b, []byte("\n"))
	for _, f := range strings.Fields(string(line)) {
		if v, ok := strings.CutPrefix(f, "groups="); ok && v != "" {
			groups = strings.Split(v, ",")
		}
		if v, ok := strings.CutPrefix(f, "recipients="); ok {
			hash = v
		}
	}
	return groups, hash
}

var ErrNoAccess = errors.New("no identity can decrypt this (you are not in an allowed group)")

func Open(b []byte, ids []age.Identity) ([]byte, error) {
	if !IsSealed(b) {
		return nil, errors.New("not a veil-encrypted blob")
	}
	if len(ids) == 0 {
		return nil, ErrNoAccess
	}
	i := bytes.Index(b, []byte(armor.Header))
	if i < 0 {
		return nil, errors.New("malformed veil blob")
	}
	r, err := age.Decrypt(armor.NewReader(bytes.NewReader(b[i:])), ids...)
	if err != nil {
		var nm *age.NoIdentityMatchError
		if errors.As(err, &nm) {
			return nil, ErrNoAccess
		}
		return nil, err
	}
	return io.ReadAll(r)
}

// identityPaths lists where we look for private keys: $VEIL_IDENTITY (colon separated)
// or ~/.config/veil/identity.txt plus default SSH keys.
func identityPaths() []string {
	if v := os.Getenv("VEIL_IDENTITY"); v != "" {
		return filepath.SplitList(v)
	}
	home, _ := os.UserHomeDir()
	return []string{
		DefaultIdentityPath(),
		filepath.Join(home, ".ssh", "id_ed25519"),
		filepath.Join(home, ".ssh", "id_rsa"),
	}
}

func DefaultIdentityPath() string {
	if v := os.Getenv("VEIL_IDENTITY"); v != "" {
		return filepath.SplitList(v)[0]
	}
	dir, err := os.UserConfigDir()
	if err != nil {
		home, _ := os.UserHomeDir()
		dir = filepath.Join(home, ".config")
	}
	return filepath.Join(dir, "veil", "identity.txt")
}

// Identity is a private key together with its public key string.
type Identity struct {
	age.Identity
	Public string
	Path   string
}

func LoadIdentities() []Identity {
	var out []Identity
	for _, p := range identityPaths() {
		data, err := os.ReadFile(p)
		if err != nil {
			continue
		}
		if bytes.Contains(data, []byte("AGE-SECRET-KEY-")) {
			ids, err := age.ParseIdentities(bytes.NewReader(data))
			if err != nil {
				continue
			}
			for _, id := range ids {
				pub := ""
				if x, ok := id.(*age.X25519Identity); ok {
					pub = x.Recipient().String()
				}
				out = append(out, Identity{id, pub, p})
			}
			continue
		}
		id, err := agessh.ParseIdentity(data)
		if err != nil {
			continue // e.g. passphrase-protected keys are not supported yet
		}
		pub, _ := os.ReadFile(p + ".pub")
		out = append(out, Identity{id, strings.TrimSpace(string(pub)), p})
	}
	return out
}

func ageIdentities() []age.Identity {
	var ids []age.Identity
	for _, id := range LoadIdentities() {
		ids = append(ids, id.Identity)
	}
	return ids
}

// Keygen writes a new age identity to path and returns its public key.
func Keygen(path string) (string, error) {
	if _, err := os.Stat(path); err == nil {
		return "", fmt.Errorf("%s already exists", path)
	}
	id, err := age.GenerateX25519Identity()
	if err != nil {
		return "", err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return "", err
	}
	pub := id.Recipient().String()
	content := fmt.Sprintf("# public key: %s\n%s\n", pub, id.String())
	return pub, os.WriteFile(path, []byte(content), 0o600)
}

func readLines(r io.Reader) []string {
	var out []string
	s := bufio.NewScanner(r)
	for s.Scan() {
		out = append(out, s.Text())
	}
	return out
}
