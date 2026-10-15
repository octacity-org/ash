// Package app wires configuration, transport and user-facing adapters.
package app

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	sdk "github.com/modelcontextprotocol/go-sdk/mcp"

	"ash/internal/audit"
	"ash/internal/cli"
	"ash/internal/config"
	"ash/internal/doctor"
	"ash/internal/host"
	ashmcp "ash/internal/mcp"
	"ash/internal/service"
	"ash/internal/shell/tmux"
	"ash/internal/shell/zellij"
	"ash/internal/sshconfig"
	sshtransport "ash/internal/transport/ssh"
)

func Run(ctx context.Context, args []string, in io.Reader, out, errout io.Writer) int {
	fail := func(err error) int { fmt.Fprintln(errout, "ash:", err); return 1 }
	if len(args) == 1 && args[0] == "--version" {
		fmt.Fprintf(out, "ash %s\n", ashmcp.Version)
		return 0
	}
	path, err := config.DefaultPath()
	if err != nil {
		return fail(err)
	}
	if len(args) > 0 && (args[0] == "--config" || strings.HasPrefix(args[0], "--config=")) {
		if args[0] == "--config" {
			if len(args) < 2 {
				return fail(fmt.Errorf("--config requires a path"))
			}
			path = args[1]
			args = args[2:]
		} else {
			path = strings.TrimPrefix(args[0], "--config=")
			args = args[1:]
		}
	}
	if len(args) == 0 || args[0] == "--help" || args[0] == "-h" {
		return cli.Run(ctx, args, nil, nil, in, out, errout)
	}
	if args[0] == "host" {
		if len(args) < 2 || args[1] != "add" {
			return fail(fmt.Errorf("usage: ash [--config PATH] host add NAME (--address ADDRESS --user USER | --ssh-alias ALIAS)"))
		}
		return cli.HostAdd(args[2:], path, out, errout)
	}
	if args[0] == "setup" {
		exe, err := os.Executable()
		if err != nil {
			return fail(err)
		}
		return cli.Setup(args[1:], exe, path, out, errout)
	}
	c, err := config.Load(path)
	if err != nil {
		return fail(err)
	}
	// Resolve OpenSSH aliases once before building the host registry. Hosts
	// without ssh_alias keep the pure-Go behavior and never invoke OpenSSH.
	for name, h := range c.Hosts {
		if h.SSHAlias == "" {
			continue
		}
		effective, err := sshconfig.Resolve(ctx, h.SSHAlias)
		if err != nil {
			return fail(fmt.Errorf("host %q: %w", name, err))
		}
		c.Hosts[name] = effective.Apply(h)
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return fail(err)
	}
	t, err := sshtransport.New(filepath.Join(home, ".ssh", "known_hosts"))
	if err != nil {
		return fail(err)
	}
	defer t.Close()
	hosts := host.New(c.Hosts)
	s := service.New(hosts, t)
	shells := service.NewShellsWithBackends(hosts, zellij.New(t), tmux.New(t)).WithCanonicalizer(t)
	if args[0] == "doctor" {
		return cli.Doctor(ctx, args[1:], doctor.New(hosts, t, filepath.Join(home, ".ssh", "known_hosts")), out, errout)
	}
	if c.AuditLog != "" {
		recorder, err := audit.New(c.AuditLog)
		if err != nil {
			return fail(err)
		}
		s.WithAudit(recorder)
		shells.WithAudit(recorder)
	}
	if args[0] == "mcp" {
		if len(args) != 1 {
			return fail(fmt.Errorf("mcp takes no arguments"))
		}
		if err := ashmcp.New(s, shells).Run(ctx, &sdk.IOTransport{Reader: readCloser(in), Writer: writeCloser(out)}); err != nil && ctx.Err() == nil {
			return fail(err)
		}
		return 0
	}
	return cli.Run(ctx, args, s, shells, in, out, errout)
}

func readCloser(r io.Reader) io.ReadCloser {
	if c, ok := r.(io.ReadCloser); ok {
		return c
	}
	return io.NopCloser(r)
}

type nopWriteCloser struct{ io.Writer }

func (nopWriteCloser) Close() error { return nil }
func writeCloser(w io.Writer) io.WriteCloser {
	if c, ok := w.(io.WriteCloser); ok {
		return c
	}
	return nopWriteCloser{w}
}
