# veil

Fine-grained access control for git repos: private files, private branches, and secrets, enforced with [age](https://age-encryption.org) encryption.

Git hosting is all-or-nothing: anyone who can clone a repo can read every file, every branch and every committed secret. veil lets one repo hold content that only some people can read, without a separate service:

- **Private files.** `private/**` is readable only by the `core` group. Everyone else sees ciphertext.
- **Private branches.** Branch `exp/*` is shared only with 3 teammates.
- **Secrets.** `PROD_*` secrets are readable only by `infra`, and the rest by everyone, all versioned in the repo.

The rules live in one committed file, `.veil/policy.yaml`:

```yaml
members:
  alice: age1qyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqs3290gq
  bob: ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI...   # SSH keys work too
  carol: age1...

groups:
  core: [alice, bob]
  infra: [alice]
  everyone: [alice, bob, carol]

files:              # first match wins; .gitattributes pattern semantics
  - match: "private/**"
    groups: [core]
  - match: "*.pem"
    groups: [infra]

branches:
  - match: "exp/*"
    groups: [core]

secrets:
  - match: "PROD_*"
    groups: [infra]
  - match: "*"
    groups: [everyone]
```

## Install

```sh
go install github.com/wholien/veil@latest
```

## Quickstart

```sh
veil keygen          # creates ~/.config/veil/identity.txt and prints your public key
cd my-repo
veil init            # writes a starter .veil/policy.yaml, installs git filters, syncs .gitattributes
git add .veil .gitattributes && git commit -m "add veil"
```

After cloning a repo that uses veil:

```sh
veil install         # configure git filters + pre-push hook for this clone
veil unlock          # decrypt the private files you have access to
veil whoami          # see which groups you're in
```

### Private files

Files that match a `files` rule go through a git clean/smudge filter. On `git add` they are encrypted to the rule's groups. On checkout they are decrypted if you hold a matching key and left as ciphertext otherwise. `git diff` and `git log -p` show plaintext to people who have access. People without access can still work normally: they see the files as ciphertext, and their commits keep those files unchanged.

```sh
veil status          # each private file: readable / locked / PLAINTEXT IN INDEX
```

After editing `files` rules, run `veil sync` to regenerate `.gitattributes`.

### Secrets

```sh
veil secret set PROD_DB 'postgres://...'   # or pipe the value on stdin
veil secret get PROD_DB
veil secret ls
veil run -- npm start                      # every secret you can read becomes an env var
```

Secrets are stored as `.veil/secrets/NAME.age`. Commit them like any other file.

### Private branches

```sh
git checkout -b exp/new-pricing
# ...commit...
git push origin exp/new-pricing                   # blocked by veil's pre-push hook
veil branch push exp/new-pricing --remote origin  # encrypts the branch and pushes it

# a teammate in the group:
veil branch pull exp/new-pricing --remote origin
veil branch ls --remote origin
```

veil packs the branch into a `git bundle`, leaving out commits already on `--base` (default `main`). It encrypts the bundle to the branch's groups and pushes it to `refs/veil/branches/<name>`, which GitHub stores but doesn't show as a branch.

### Changing access

Edit the policy, then:

```sh
veil rekey           # re-encrypts files and secrets you can read for the new recipient set
git commit -am "grant carol access to core"
```

## How it works

- Encryption is [age](https://github.com/FiloSottile/age) (X25519 or SSH keys), ASCII-armored, with a one-line header: `# veil:v1 groups=core recipients=<hash>`.
- age is randomized, so the clean filter reuses the existing ciphertext from the index or `HEAD` when the plaintext and recipients are unchanged. This avoids phantom diffs.
- Identities come from `$VEIL_IDENTITY` (colon-separated paths) or `~/.config/veil/identity.txt`, `~/.ssh/id_ed25519` and `~/.ssh/id_rsa`. SSH keys with a passphrase are not supported yet.

## Threat model and limits

This is a sketch, not audited software. Access is enforced by encryption, not by the git server, which leads to these tradeoffs:

- **Revocation is forward-only.** Removing someone from a group protects only content encrypted after you run `veil rekey`. Anything they could read before is still in history, so rotate real secrets.
- **Metadata is visible.** File names, sizes, commit messages, group names, and the existence of private branches are visible to anyone with repo access.
- **The policy is not authenticated.** Anyone who can push can edit `.veil/policy.yaml` to add their own key. They still can't read existing content, but anything encrypted after that change will include them. Protect the file with CODEOWNERS or branch protection, or review policy changes.
- **History stays plaintext.** Adding a rule for a file that was already committed doesn't encrypt its old versions.
- **Filters must be installed.** Without `veil install`, git can't run the filter. `filter.veil.required=true` makes commits fail instead of leaking, but only after the filter is configured. `veil status` flags plaintext that slipped into the index.

## Development

```sh
go test ./...        # includes an end-to-end test with two users and a bare remote
```
