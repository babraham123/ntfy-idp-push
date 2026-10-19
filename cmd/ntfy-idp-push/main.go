// Command ntfy-idp-push is a Duo Auth API stand-in that delivers sign-in approvals over ntfy.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"runtime/debug"
	"slices"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/babraham123/ntfy-idp-push/internal/app"
	"github.com/babraham123/ntfy-idp-push/internal/config"
	"github.com/babraham123/ntfy-idp-push/internal/core"
	"github.com/babraham123/ntfy-idp-push/internal/model"
	"github.com/babraham123/ntfy-idp-push/internal/store"
	"github.com/babraham123/ntfy-idp-push/internal/token"
)

const usage = `Usage: ntfy-idp-push [-c config.yml] <command> [args]

Commands:
  serve                                   run the server
  keygen [--rotate]                       print new Duo integration/secret keys, or rotate the secret key in the config file
  user list
  user provision <username> [--email <addr>]
                                          create the ntfy account of a directory user, or with no directory
                                          of the user at <addr>, apply enroll-access and send the welcome
                                          email if it was never sent (no push device)
  user welcome <username>                 set a new ntfy password and email it in a new welcome email
  user disable|enable <username>          block or allow sign-in; the directory sync never changes it
  user delete <username> [--keep-ntfy-user]
  user approve <challenge-id>             approve a pending login without a passkey (break-glass)
  user reset-ntfy <username> [--force]    recreate the ntfy user, invalidating all of its tokens, and send
                                          a new welcome email
  device list <username>
  device revoke <device-id> [--reset-ntfy-user] [--force]
  enroll-link <username>                  print a single-use enrollment link, valid 5 minutes
  audit [username]                        print the last 100 audit entries
  backup <path>|-                         write a consistent copy of the database, safe while serving
  healthcheck [url]                       exit 0 if url (default http://127.0.0.1:8080/healthz) answers 200
  version

The config path defaults to $NTFY_IDP_PUSH_CONFIG, then /etc/ntfy-idp-push/server.yml.
Every key can be set as NTFY_IDP_PUSH_<KEY> (e.g. NTFY_IDP_PUSH_DUO_SECRET_KEY). Secrets can be read
from a file with <key>-file or NTFY_IDP_PUSH_<KEY>_FILE (e.g. NTFY_IDP_PUSH_DUO_SECRET_KEY_FILE).
`

// version is stamped by -ldflags "-X main.version=…" in release builds and the image.
var version = "dev"

// buildVersion falls back to the module version (go install) or git pseudo-version (go build).
func buildVersion() string {
	if version != "dev" {
		return version
	}
	if bi, ok := debug.ReadBuildInfo(); ok && bi.Main.Version != "" && bi.Main.Version != "(devel)" {
		return bi.Main.Version
	}
	return version
}

func main() {
	log := slog.New(slog.NewTextHandler(os.Stderr, nil))
	if err := run(os.Args[1:], os.Stdout, log); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

// splitArgs separates flags from positionals so flags may follow positional arguments. The flags
// named in valued take a value, which may be the next argument. Everything after "--" is
// positional, which is how a username that starts with "-" is passed.
func splitArgs(args []string, valued ...string) (flags, pos []string) {
	for i := 0; i < len(args); i++ {
		a := args[i]
		if a == "--" {
			return flags, append(pos, args[i+1:]...)
		}
		if !strings.HasPrefix(a, "-") {
			pos = append(pos, a)
			continue
		}
		flags = append(flags, a)
		if slices.Contains(valued, strings.TrimLeft(a, "-")) && i+1 < len(args) {
			i++
			flags = append(flags, args[i])
		}
	}
	return flags, pos
}

// run executes one CLI invocation, printing results to out.
func run(args []string, out io.Writer, log *slog.Logger) error {
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
		return keygen(*cfgPath, rest, out)
	case "healthcheck":
		return healthcheck(rest)
	case "version":
		fmt.Fprintln(out, buildVersion())
		return nil
	}
	// A missing default config file is ignored if environment variables suffice, but explicit
	// paths must exist.
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
		return serve(cfg, path, log)
	}
	a, err := app.Open(cfg, log)
	if err != nil {
		return err
	}
	defer a.Close()
	svc := a.Svc
	ctx := context.Background()
	switch cmd {
	case "user":
		return userCmd(ctx, svc, rest, out)
	case "device":
		return deviceCmd(ctx, svc, rest, out)
	case "enroll-link":
		if len(rest) != 1 {
			return errors.New("usage: enroll-link <username>")
		}
		_, link, _, err := svc.CreateEnrollCode(ctx, rest[0], core.EnrollCodeTTL)
		if err != nil {
			return err
		}
		fmt.Fprintln(out, link)
		return nil
	case "backup":
		if len(rest) != 1 {
			return errors.New("usage: backup <path>|-")
		}
		return backup(ctx, a.Store, filepath.Dir(cfg.Database), rest[0], out)
	case "audit":
		user := ""
		if len(rest) > 0 {
			user = rest[0]
		}
		entries, err := svc.AuditLog(ctx, user, 100)
		if err != nil {
			return err
		}
		tw := tabwriter.NewWriter(out, 0, 4, 2, ' ', 0)
		for _, e := range entries {
			fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n", e.TS.Format(time.RFC3339), e.Username, e.Event, e.Detail)
		}
		return tw.Flush()
	}
	global.Usage()
	return fmt.Errorf("unknown command %q", cmd)
}

// backup writes the database copy to path, or to out for "-" via a temporary file in dir.
func backup(ctx context.Context, st *store.Store, dir, path string, out io.Writer) error {
	if path != "-" {
		return st.Backup(ctx, path)
	}
	tmp := filepath.Join(dir, ".backup-"+token.Random(8)+".sqlite")
	if err := st.Backup(ctx, tmp); err != nil {
		return err
	}
	defer os.Remove(tmp)
	f, err := os.Open(tmp)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = io.Copy(out, f)
	return err
}

func keygen(cfgPath string, args []string, out io.Writer) error {
	fs := flag.NewFlagSet("keygen", flag.ContinueOnError)
	rotate := fs.Bool("rotate", false, "rotate duo-secret-key in the config file")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if !*rotate {
		fmt.Fprintf(out, "duo-integration-key: %q\nduo-secret-key: %q\n", config.NewIntegrationKey(), config.NewSecretKey())
		return nil
	}
	key, err := config.RotateSecretKey(cfgPath, time.Now())
	if err != nil {
		return err
	}
	fmt.Fprintf(out, "rotated duo-secret-key in %s; the previous key is accepted for duo-key-grace after a reload.\n", cfgPath)
	fmt.Fprintf(out, "set the IdP's secret key to: %s\n", key)
	return nil
}

func userCmd(ctx context.Context, svc *core.Service, args []string, out io.Writer) error {
	flags, pos := splitArgs(args, "email")
	if len(pos) == 0 {
		return errors.New("usage: user list|provision|welcome|disable|enable|delete|approve|reset-ntfy [args]")
	}
	fs := flag.NewFlagSet("user", flag.ContinueOnError)
	email := fs.String("email", "", "the address to provision a user at when no directory is configured")
	keepNtfy := fs.Bool("keep-ntfy-user", false, "keep the ntfy user when deleting")
	force := fs.Bool("force", false, "reset-ntfy even if the ntfy user has grants the shim did not make")
	if err := fs.Parse(flags); err != nil {
		return err
	}
	sub := pos[0]
	if sub == "list" {
		users, err := svc.Users(ctx)
		if err != nil {
			return err
		}
		tw := tabwriter.NewWriter(out, 0, 4, 2, ' ', 0)
		fmt.Fprintln(tw, "USERNAME\tID\tEMAIL\tDEVICES\tSTATUS\tWELCOMED\tSYNCED")
		for _, u := range users {
			st := "active"
			if !u.Enabled() {
				st = "disabled"
			}
			email := u.Email
			if email == "" {
				email = "-"
			}
			fmt.Fprintf(tw, "%s\t%s\t%s\t%d\t%s\t%s\t%s\n", u.Username, u.ID, email, u.ActiveDevices, st,
				fmtTime(u.WelcomedAt), fmtTime(u.SyncedAt))
		}
		return tw.Flush()
	}
	if len(pos) != 2 {
		return fmt.Errorf("usage: user %s <arg>", sub)
	}
	arg := pos[1]
	switch sub {
	case "provision":
		var u *model.User
		var err error
		if *email != "" {
			u, err = svc.ProvisionManual(ctx, arg, *email)
		} else {
			u, err = svc.ProvisionFromDirectory(ctx, arg)
		}
		switch {
		case errors.Is(err, core.ErrDirectoryConfigured):
			return fmt.Errorf("--email refused: %w", err)
		case errors.Is(err, core.ErrNoDirectory):
			return fmt.Errorf("%w: user provision needs --email <addr>", err)
		}
		if u != nil {
			for _, g := range u.Grants {
				fmt.Fprintf(out, "%s\t%s\n", g.Topic, g.Permission)
			}
		}
		if err != nil && u != nil {
			return fmt.Errorf("provisioned, but no welcome email was sent: %w", err)
		}
		return err
	case "welcome":
		if err := svc.Welcome(ctx, arg); err != nil {
			return err
		}
		fmt.Fprintln(out, "welcome email sent with a new ntfy password; older passwords fail")
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
		fmt.Fprintln(out, "ntfy user recreated: every phone must sign in with the credentials from the new welcome email")
		return nil
	}
	return fmt.Errorf("unknown user command %q", sub)
}

func deviceCmd(ctx context.Context, svc *core.Service, args []string, out io.Writer) error {
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
		_, devs, err := svc.DevicesOf(ctx, pos[1])
		if err != nil {
			return err
		}
		tw := tabwriter.NewWriter(out, 0, 4, 2, ' ', 0)
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
			fmt.Fprintln(out, "revoked; ntfy user recreated: every phone must sign in with the credentials from the new welcome email")
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

// healthcheck probes the local listener.
func healthcheck(args []string) error {
	u := "http://127.0.0.1:8080/healthz"
	if len(args) > 0 {
		u = args[0]
	}
	c := &http.Client{Timeout: 4 * time.Second}
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
