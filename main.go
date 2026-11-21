// Command veil adds per-group access control to a git repository:
// private files, private branches and secrets, enforced with age encryption.
package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/wholien/veil/internal/veil"
)

const usage = `veil: fine-grained access control for git repos

Setup:
  veil keygen                     create an age identity (~/.config/veil/identity.txt)
  veil init                       create .veil/policy.yaml, install filters, sync .gitattributes
  veil install                    configure this clone (run once after cloning)
  veil sync                       regenerate .gitattributes from the policy
  veil whoami                     show your public keys and groups

Private files:
  veil unlock                     decrypt private files you have access to
  veil status                     show private files and whether you can read them
  veil rekey                      re-encrypt files and secrets after policy changes

Secrets:
  veil secret set NAME [VALUE]    store a secret (reads stdin if VALUE is omitted)
  veil secret get NAME            print a secret
  veil secret ls                  list secrets
  veil secret rm NAME             delete a secret
  veil run -- CMD [ARGS...]       run CMD with readable secrets as env vars

Private branches:
  veil branch push NAME [--remote origin] [--base main]
  veil branch pull NAME [--remote origin]
  veil branch ls [--remote origin]
`

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(args []string) error {
	if len(args) == 0 {
		fmt.Print(usage)
		return nil
	}
	out := os.Stdout
	cmd, rest := args[0], args[1:]
	switch cmd {
	case "keygen":
		path := veil.DefaultIdentityPath()
		pub, err := veil.Keygen(path)
		if err != nil {
			return err
		}
		fmt.Fprintf(out, "wrote %s\npublic key: %s\n", path, pub)
		return nil
	case "init":
		return veil.Init(out)
	case "install":
		return veil.Install(out)
	case "sync":
		return veil.Sync(out)
	case "whoami":
		return veil.Whoami(out)
	case "unlock":
		return veil.Unlock(out)
	case "status":
		return veil.Status(out)
	case "rekey":
		return veil.Rekey(out)
	case "secret":
		return secretCmd(rest)
	case "run":
		if len(rest) > 0 && rest[0] == "--" {
			rest = rest[1:]
		}
		code, err := veil.Run(rest)
		if err != nil {
			return err
		}
		os.Exit(code)
	case "branch":
		return branchCmd(rest)

	// Plumbing invoked by git.
	case "clean", "smudge":
		if len(rest) != 1 {
			return fmt.Errorf("usage: veil %s <path>", cmd)
		}
		in, err := io.ReadAll(os.Stdin)
		if err != nil {
			return err
		}
		res := veil.Smudge(in)
		if cmd == "clean" {
			if res, err = veil.Clean(rest[0], in); err != nil {
				return err
			}
		}
		_, err = out.Write(res)
		return err
	case "textconv":
		if len(rest) != 1 {
			return errors.New("usage: veil textconv <file>")
		}
		return veil.Textconv(rest[0], out)
	case "hook":
		if len(rest) > 0 && rest[0] == "pre-push" {
			return veil.HookPrePush(os.Stdin)
		}
		return errors.New("usage: veil hook pre-push")
	case "help", "-h", "--help":
		fmt.Print(usage)
		return nil
	}
	return fmt.Errorf("unknown command %q; run `veil help`", cmd)
}

func secretCmd(args []string) error {
	if len(args) == 0 {
		return errors.New("usage: veil secret set|get|ls|rm")
	}
	switch args[0] {
	case "set":
		if len(args) < 2 || len(args) > 3 {
			return errors.New("usage: veil secret set NAME [VALUE]")
		}
		var val []byte
		if len(args) == 3 {
			val = []byte(args[2])
		} else {
			var err error
			if val, err = io.ReadAll(os.Stdin); err != nil {
				return err
			}
		}
		return veil.SecretSet(args[1], val)
	case "get":
		if len(args) != 2 {
			return errors.New("usage: veil secret get NAME")
		}
		v, err := veil.SecretGet(args[1])
		if err != nil {
			return err
		}
		_, err = os.Stdout.Write(v)
		return err
	case "ls":
		return veil.SecretList(os.Stdout)
	case "rm":
		if len(args) != 2 {
			return errors.New("usage: veil secret rm NAME")
		}
		return veil.SecretRemove(args[1])
	}
	return fmt.Errorf("unknown secret command %q", args[0])
}

func branchCmd(args []string) error {
	if len(args) == 0 {
		return errors.New("usage: veil branch push|pull|ls")
	}
	sub := args[0]
	fs := flag.NewFlagSet("branch "+sub, flag.ContinueOnError)
	remote := fs.String("remote", "", "remote to push to / fetch from")
	base := fs.String("base", "main", "commits reachable from this ref are left out of the bundle")
	// Allow the branch name before or after flags.
	var name string
	rest := args[1:]
	if len(rest) > 0 && rest[0] != "" && rest[0][0] != '-' {
		name, rest = rest[0], rest[1:]
	}
	if err := fs.Parse(rest); err != nil {
		return err
	}
	if name == "" && fs.NArg() > 0 {
		name = fs.Arg(0)
	}
	switch sub {
	case "push", "pull":
		if name == "" {
			return fmt.Errorf("usage: veil branch %s NAME [--remote origin]", sub)
		}
		if sub == "push" {
			return veil.BranchPush(name, *remote, *base, os.Stdout)
		}
		return veil.BranchPull(name, *remote, os.Stdout)
	case "ls":
		return veil.BranchList(*remote, os.Stdout)
	}
	return fmt.Errorf("unknown branch command %q", sub)
}
