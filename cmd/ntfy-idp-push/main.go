// Command ntfy-idp-push is a Duo Auth API stand-in that delivers sign-in approvals over ntfy.
package main

import (
	"context"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"runtime/debug"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/babraham123/ntfy-idp-push/internal/challenge"
	"github.com/babraham123/ntfy-idp-push/internal/config"
	"github.com/babraham123/ntfy-idp-push/internal/core"
	"github.com/babraham123/ntfy-idp-push/internal/store"
)

const usage = `Usage: ntfy-idp-push [-c config.yml] <command> [args]

Commands:
  serve                                   run the server
  keygen [--rotate]                       print new Duo integration/secret keys, or rotate the secret key in the config file
  user list
  user provision <username>               create the ntfy account and apply enroll-access (no push device)
  user disable|enable <username>
  user delete <username> [--keep-ntfy-user]
  user approve <challenge-id>             approve a pending login without a passkey (break-glass)
  user reset-ntfy <username> [--force]    recreate the ntfy user, invalidating all of its tokens
  device list <username>
  device revoke <device-id> [--reset-ntfy-user] [--force]
  enroll-link <username>                  print a single-use enrollment link, valid 5 minutes
  audit [username]                        print the last 100 audit entries
  backup <path>|-                         write a consistent copy of the database, safe while serving
  healthcheck [url]                       exit 0 if url (default https://127.0.0.1:8443/healthz) answers 200
  version

The config path defaults to $NTFY_IDP_PUSH_CONFIG, then /etc/ntfy-idp-push/server.yml.
Every key can be set as NTFY_IDP_PUSH_<KEY> (e.g. NTFY_IDP_PUSH_DUO_SECRET_KEY). Secrets can be read
from a file with <key>-file or NTFY_IDP_PUSH_<KEY>_FILE (e.g. NTFY_IDP_PUSH_DUO_SECRET_KEY_FILE).
`

// version is stamped by -ldflags "-X main.version=…" in release builds and the image.
var version = "dev"

// buildVersion falls back to the version the Go toolchain records: the module version for
// go install …@v1.2.3, or a pseudo-version from git for a plain go build in a checkout.
func buildVersion() string {
	if bi, ok := debug.ReadBuildInfo(); ok && version == "dev" && bi.Main.Version != "" && bi.Main.Version != "(devel)" {
		return bi.Main.Version
	}
	return version
}

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

// splitArgs separates flags from positionals so flags may follow positional arguments.
func splitArgs(args []string) (flags, pos []string) {
	for _, a := range args {
		if strings.HasPrefix(a, "-") {
			flags = append(flags, a)
		} else {
			pos = append(pos, a)
		}
	}
	return flags, pos
}

func run(args []string) error {
	global := flag.NewFlagSet("ntfy-idp-push", flag.ContinueOnError)
	global.Usage = func() { fmt.Fprint(os.Stderr, usage) }
	defaultPath := os.Getenv("NTFY_IDP_PUSH_CONFIG")
	if defaultPath == "" {
		defaultPath = "/etc/ntfy-idp-push/server.yml"
	}
	cfgPath := global.String("c", defaultPath, "config file")
	global.StringVar(cfgPath, "config", defaultPath, "config file")
	if err := global.Parse(args); err != nil {
		return err
	}
	args = global.Args()
	if len(args) == 0 {
		global.Usage()
		return errors.New("no command")
	}
	cmd, rest := args[0], args[1:]
	switch cmd {
	case "keygen":
		return keygen(*cfgPath, rest)
	case "healthcheck":
		return healthcheck(rest)
	case "version":
		fmt.Println(buildVersion())
		return nil
	}
	// A missing default config file is fine when everything comes from the environment; a path
	// given explicitly must exist.
	path, explicit := *cfgPath, os.Getenv("NTFY_IDP_PUSH_CONFIG") != ""
	global.Visit(func(f *flag.Flag) { explicit = explicit || f.Name == "c" || f.Name == "config" })
	if _, err := os.Stat(path); errors.Is(err, os.ErrNotExist) && !explicit {
		path = ""
	}
	cfg, err := config.Load(path)
	if err != nil {
		return err
	}
	if cmd == "serve" {
		return serve(cfg, path)
	}
	svc, closeFn, err := open(cfg)
	if err != nil {
		return err
	}
	defer closeFn()
	ctx := context.Background()
	switch cmd {
	case "user":
		return userCmd(ctx, svc, rest)
	case "device":
		return deviceCmd(ctx, svc, rest)
	case "enroll-link":
		if len(rest) != 1 {
			return errors.New("usage: enroll-link <username>")
		}
		_, link, err := svc.CreateEnrollCode(ctx, rest[0], core.EnrollCodeTTL)
		if err != nil {
			return err
		}
		fmt.Println(link)
		return nil
	case "backup":
		if len(rest) != 1 {
			return errors.New("usage: backup <path>|-")
		}
		return backup(ctx, svc.Store, filepath.Dir(cfg.Database), rest[0])
	case "audit":
		user := ""
		if len(rest) > 0 {
			user = rest[0]
		}
		entries, err := svc.Store.AuditLog(ctx, user, 100)
		if err != nil {
			return err
		}
		tw := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
		for _, e := range entries {
			fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n", e.TS.Format(time.RFC3339), e.Username, e.Event, e.Detail)
		}
		return tw.Flush()
	}
	global.Usage()
	return fmt.Errorf("unknown command %q", cmd)
}

func open(cfg *config.Config) (*core.Service, func(), error) {
	st, err := store.Open(cfg.Database)
	if err != nil {
		return nil, nil, err
	}
	log := slog.New(slog.NewTextHandler(os.Stderr, nil))
	svc, err := core.New(cfg, st, log)
	if err != nil {
		st.Close()
		return nil, nil, err
	}
	return svc, func() { st.Close() }, nil
}

// backup writes the database copy to path, or to stdout for "-" by way of a temporary file in dir
// (the state volume in a container, which is writable).
func backup(ctx context.Context, st *store.Store, dir, path string) error {
	if path != "-" {
		return st.Backup(ctx, path)
	}
	tmp := filepath.Join(dir, ".backup-"+challenge.RandomToken(8)+".sqlite")
	if err := st.Backup(ctx, tmp); err != nil {
		return err
	}
	defer os.Remove(tmp)
	f, err := os.Open(tmp)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = io.Copy(os.Stdout, f)
	return err
}

func keygen(cfgPath string, args []string) error {
	fs := flag.NewFlagSet("keygen", flag.ContinueOnError)
	rotate := fs.Bool("rotate", false, "rotate duo-secret-key in the config file")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if !*rotate {
		fmt.Printf("duo-integration-key: %q\nduo-secret-key: %q\n", config.NewIntegrationKey(), config.NewSecretKey())
		return nil
	}
	key, err := config.RotateSecretKey(cfgPath, time.Now())
	if err != nil {
		return err
	}
	fmt.Printf("rotated duo-secret-key in %s; the previous key is accepted for duo-key-grace after a reload.\n", cfgPath)
	fmt.Printf("set the IdP's secret key to: %s\n", key)
	return nil
}

func userCmd(ctx context.Context, svc *core.Service, args []string) error {
	flags, pos := splitArgs(args)
	if len(pos) == 0 {
		return errors.New("usage: user list|provision|disable|enable|delete|approve|reset-ntfy [args]")
	}
	fs := flag.NewFlagSet("user", flag.ContinueOnError)
	keepNtfy := fs.Bool("keep-ntfy-user", false, "keep the ntfy user when deleting")
	force := fs.Bool("force", false, "reset-ntfy even if the ntfy user has grants the shim did not make")
	if err := fs.Parse(flags); err != nil {
		return err
	}
	sub := pos[0]
	if sub == "list" {
		users, err := svc.Store.Users(ctx)
		if err != nil {
			return err
		}
		tw := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
		fmt.Fprintln(tw, "USERNAME\tID\tDEVICES\tSTATUS")
		for _, u := range users {
			devs, err := svc.Store.Devices(ctx, u.ID, true)
			if err != nil {
				return err
			}
			st := "active"
			if u.DisabledAt != nil {
				st = "disabled"
			}
			fmt.Fprintf(tw, "%s\t%s\t%d\t%s\n", u.Username, u.ID, len(devs), st)
		}
		return tw.Flush()
	}
	if len(pos) != 2 {
		return fmt.Errorf("usage: user %s <arg>", sub)
	}
	arg := pos[1]
	switch sub {
	case "provision":
		u, err := svc.Provision(ctx, arg)
		if err != nil {
			return err
		}
		for _, g := range u.Grants {
			fmt.Printf("%s\t%s\n", g.Topic, g.Permission)
		}
		return nil
	case "disable", "enable":
		return svc.SetUserDisabled(ctx, arg, sub == "disable")
	case "delete":
		return svc.DeleteUser(ctx, arg, *keepNtfy)
	case "approve":
		return svc.AdminApprove(ctx, arg)
	case "reset-ntfy":
		if err := svc.ResetNtfyUser(ctx, arg, *force); err != nil {
			return err
		}
		fmt.Println("ntfy user recreated: every enrolled phone must re-open its ntfy link")
		return nil
	}
	return fmt.Errorf("unknown user command %q", sub)
}

func deviceCmd(ctx context.Context, svc *core.Service, args []string) error {
	flags, pos := splitArgs(args)
	fs := flag.NewFlagSet("device", flag.ContinueOnError)
	reset := fs.Bool("reset-ntfy-user", false, "recreate the ntfy user to invalidate all its tokens")
	force := fs.Bool("force", false, "reset even if the ntfy user has grants the shim did not make")
	if err := fs.Parse(flags); err != nil {
		return err
	}
	if len(pos) != 2 {
		return errors.New("usage: device list <username> | device revoke <device-id> [--reset-ntfy-user] [--force]")
	}
	switch pos[0] {
	case "list":
		u, err := svc.Store.UserByName(ctx, pos[1])
		if err != nil {
			return err
		}
		devs, err := svc.Store.Devices(ctx, u.ID, false)
		if err != nil {
			return err
		}
		tw := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
		fmt.Fprintln(tw, "ID\tNAME\tTOPIC\tVERIFIED\tLAST USED\tREVOKED")
		for _, d := range devs {
			fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\n", d.ID, d.Name, d.NtfyTopic, fmtTime(d.VerifiedAt), fmtTime(d.LastUsedAt), fmtTime(d.RevokedAt))
		}
		return tw.Flush()
	case "revoke":
		if err := svc.RevokeDevice(ctx, pos[1], *reset, *force, "cli"); err != nil {
			return err
		}
		if *reset {
			fmt.Println("revoked; ntfy user recreated: other enrolled phones must re-open their ntfy link")
		}
		return nil
	}
	return fmt.Errorf("unknown device command %q", pos[0])
}

func fmtTime(t *time.Time) string {
	if t == nil {
		return "-"
	}
	return t.Format(time.RFC3339)
}

// healthcheck probes the local listener; the certificate is for the public name, not 127.0.0.1.
func healthcheck(args []string) error {
	u := "https://127.0.0.1:8443/healthz"
	if len(args) > 0 {
		u = args[0]
	}
	c := &http.Client{Timeout: 4 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}}
	resp, err := c.Get(u)
	if err != nil {
		return err
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("%s: %s", u, resp.Status)
	}
	return nil
}
