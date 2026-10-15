// Package doctor reports local configuration and per-host remote diagnostics.
//
// Diagnostics are read-only and never print identity paths, key material, or
// environment secrets. Remote checks go through the same verified SSH transport
// as ordinary operations.
package doctor

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"

	"ash/internal/host"
	"ash/internal/transport"
)

type Status string

const (
	StatusOK   Status = "ok"
	StatusFail Status = "fail"
	StatusWarn Status = "warn"
	StatusSkip Status = "skip"
)

type Check struct {
	Name    string `json:"name"`
	Status  Status `json:"status"`
	Message string `json:"message"`
	Hint    string `json:"hint,omitempty"`
}

type Report struct {
	Host   string  `json:"host,omitempty"`
	Checks []Check `json:"checks"`
}

// Failed reports whether any check needs attention.
func (r Report) Failed() bool {
	for _, c := range r.Checks {
		if c.Status == StatusFail {
			return true
		}
	}
	return false
}

type Doctor struct {
	hosts          *host.Registry
	transport      transport.Transport
	knownHostsPath string
}

func New(hosts *host.Registry, t transport.Transport, knownHostsPath string) *Doctor {
	return &Doctor{hosts: hosts, transport: t, knownHostsPath: knownHostsPath}
}

// Local reports configuration and trust-file checks without any network access.
func (d *Doctor) Local() Report {
	report := Report{}
	report.Checks = append(report.Checks, Check{Name: "config", Status: StatusOK, Message: "configuration parsed"})
	hosts := d.hosts.List()
	names := make([]string, 0, len(hosts))
	for _, h := range hosts {
		names = append(names, h.Name)
	}
	report.Checks = append(report.Checks, Check{Name: "hosts", Status: StatusOK, Message: fmt.Sprintf("%d host(s) configured", len(hosts))})
	report.Checks = append(report.Checks, d.knownHostsCheck())
	return report
}

// Run runs local checks and, when name is set, remote checks for that host.
func (d *Doctor) Run(ctx context.Context, name string) Report {
	if name == "" {
		return d.Local()
	}
	report := d.Local()
	report.Host = name
	h, err := d.hosts.Get(name)
	if err != nil {
		report.Checks = append(report.Checks, Check{Name: "host", Status: StatusFail, Message: err.Error(), Hint: "add it with: ash host add " + name + " --address ADDRESS --user USER"})
		return report
	}
	report.Checks = append(report.Checks, Check{Name: "host", Status: StatusOK, Message: fmt.Sprintf("%s@%s:%d", h.User, h.Address, h.Port)})
	report.Checks = append(report.Checks, Check{Name: "policy", Status: StatusOK, Message: capabilities(h)})

	if _, err := d.exec(ctx, h, "true"); err != nil {
		report.Checks = append(report.Checks, classify(err))
		return report
	}
	report.Checks = append(report.Checks,
		Check{Name: "trust", Status: StatusOK, Message: "host key verified"},
		Check{Name: "auth", Status: StatusOK, Message: "SSH authentication succeeded"},
	)
	if !h.Policy.Exec {
		report.Checks = append(report.Checks, Check{Name: "shell", Status: StatusSkip, Message: "exec capability is not granted", Hint: "set [hosts." + name + ".policy] exec = true to run remote diagnostics"})
		return report
	}
	report.Checks = append(report.Checks, d.shellCheck(ctx, h))
	report.Checks = append(report.Checks, d.cacheCheck(ctx, h))
	report.Checks = append(report.Checks, d.backendCheck(ctx, h))
	return report
}

func (d *Doctor) knownHostsCheck() Check {
	if _, err := os.Stat(d.knownHostsPath); err != nil {
		return Check{Name: "known_hosts", Status: StatusWarn, Message: "no known_hosts file found", Hint: "establish trust first: ssh USER@ADDRESS"}
	}
	return Check{Name: "known_hosts", Status: StatusOK, Message: "known_hosts file present"}
}

func (d *Doctor) shellCheck(ctx context.Context, h host.Host) Check {
	r, err := d.exec(ctx, h, "command -v sh")
	if err != nil || r.ExitCode != 0 {
		return Check{Name: "shell", Status: StatusFail, Message: "no POSIX shell on PATH", Hint: "ASH assumes a POSIX-compatible remote shell"}
	}
	return Check{Name: "shell", Status: StatusOK, Message: "POSIX shell available"}
}

// cacheCheckCommand reports the remote cache state through distinct exit
// codes in one non-mutating probe:
//
//	0 = ~/.cache/ash exists and is writable
//	1 = ~/.cache/ash exists but is not writable
//	2 = ~/.cache/ash exists but is not a directory
//	3 = ~/.cache/ash is missing and the nearest creatable parent is writable
//	4 = ~/.cache exists but is not a directory
//	5 = ~/.cache/ash is missing and the nearest parent is not writable
//
// The two non-directory states get separate codes because the blocking
// component differs: when ~/.cache itself is a file, ASH cannot create the
// cache directory regardless of anything else. Combining existence and
// writability keeps a transport failure distinguishable from any shell exit
// code.
const cacheCheckCommand = `if [ -d "$HOME/.cache/ash" ]; then ` +
	`if [ -w "$HOME/.cache/ash" ]; then exit 0; else exit 1; fi; ` +
	`elif [ -e "$HOME/.cache/ash" ]; then exit 2; ` +
	`elif [ -d "$HOME/.cache" ]; then ` +
	`if [ -w "$HOME/.cache" ]; then exit 3; else exit 5; fi; ` +
	`elif [ -e "$HOME/.cache" ]; then exit 4; ` +
	`elif [ -w "$HOME" ]; then exit 3; ` +
	`else exit 5; fi`

// cacheCheck verifies the remote cache location without mutating the host:
// it inspects what exists (or what could be created) with a shell test only.
// A missing ~/.cache/ash is reported as a warning rather than created, since
// diagnostics must not change the host.
func (d *Doctor) cacheCheck(ctx context.Context, h host.Host) Check {
	r, err := d.exec(ctx, h, cacheCheckCommand)
	if err != nil {
		// A transport failure is a connectivity problem, never evidence about
		// the cache; classify it like the other remote checks instead of
		// treating the zero-value exit code as a healthy directory.
		return classify(err)
	}
	switch r.ExitCode {
	case 0:
		return Check{Name: "cache", Status: StatusOK, Message: "remote cache directory is writable"}
	case 1:
		return Check{Name: "cache", Status: StatusFail, Message: "remote cache directory is not writable", Hint: "check permissions on $HOME/.cache/ash"}
	case 2:
		return Check{Name: "cache", Status: StatusFail, Message: "$HOME/.cache/ash exists but is not a directory", Hint: "remove or rename it so ASH can create the cache directory"}
	case 3:
		return Check{Name: "cache", Status: StatusWarn, Message: "remote cache directory is missing; ASH will create it on first use", Hint: "mkdir -p ~/.cache/ash (created automatically later)"}
	case 4:
		return Check{Name: "cache", Status: StatusFail, Message: "$HOME/.cache exists but is not a directory", Hint: "remove or rename it so ASH can create the cache directory"}
	default:
		return Check{Name: "cache", Status: StatusFail, Message: "remote cache directory is missing and $HOME/.cache is not writable", Hint: "check permissions on $HOME/.cache or create it yourself"}
	}
}

// backendCheck verifies the persistent-shell backend the host is configured for.
func (d *Doctor) backendCheck(ctx context.Context, h host.Host) Check {
	if h.ShellBackend == "tmux" {
		r, err := d.exec(ctx, h, `command -v tmux >/dev/null 2>&1 && tmux -V`)
		if err != nil || r.ExitCode != 0 {
			return Check{Name: "tmux", Status: StatusWarn, Message: "tmux not found", Hint: "install tmux for persistent shells"}
		}
		return Check{Name: "tmux", Status: StatusOK, Message: firstLine(r.Stdout)}
	}
	r, err := d.exec(ctx, h, `command -v zellij >/dev/null 2>&1 && zellij --version`)
	if err != nil || r.ExitCode != 0 {
		return Check{Name: "zellij", Status: StatusWarn, Message: "Zellij not found", Hint: "install Zellij 0.44+ for persistent shells"}
	}
	return Check{Name: "zellij", Status: StatusOK, Message: firstLine(r.Stdout)}
}

func capabilities(h host.Host) string {
	caps := make([]string, 0, 3)
	if h.Policy.Exec {
		caps = append(caps, "exec")
	}
	if h.Policy.Read {
		caps = append(caps, "read")
	}
	if h.Policy.Write {
		caps = append(caps, "write")
	}
	if len(caps) == 0 {
		return "no capabilities granted"
	}
	return "granted: " + strings.Join(caps, ", ")
}

func classify(err error) Check {
	switch {
	case errors.Is(err, transport.ErrHostKey):
		return Check{Name: "trust", Status: StatusFail, Message: "host key is not trusted", Hint: "verify the fingerprint with OpenSSH: ssh USER@ADDRESS"}
	case errors.Is(err, transport.ErrAuthentication):
		return Check{Name: "auth", Status: StatusFail, Message: "SSH authentication failed", Hint: "load an unencrypted key into your SSH agent or check the configured identity"}
	case errors.Is(err, transport.ErrTimeout):
		return Check{Name: "network", Status: StatusFail, Message: "operation timed out", Hint: "check the address, port, and network reachability"}
	default:
		return Check{Name: "network", Status: StatusFail, Message: err.Error(), Hint: "check the address, port, and network reachability"}
	}
}

func (d *Doctor) exec(ctx context.Context, h host.Host, command string) (transport.ExecResult, error) {
	ctx, cancel := context.WithTimeout(ctx, transport.DefaultFileTimeout)
	defer cancel()
	return d.transport.Exec(ctx, h, transport.ExecRequest{Command: command, Timeout: transport.DefaultFileTimeout})
}

func firstLine(s string) string {
	for i := 0; i < len(s); i++ {
		if s[i] == '\n' || s[i] == '\r' {
			return s[:i]
		}
	}
	return s
}
