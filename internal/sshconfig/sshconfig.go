// Package sshconfig resolves an OpenSSH host alias into effective connection
// fields by running `ssh -G`, so Include, Match, and aliases behave exactly as
// OpenSSH does rather than being reimplemented.
package sshconfig

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os/exec"
	"sort"
	"strconv"
	"strings"

	"ash/internal/host"
)

// ErrUnsupported reports an OpenSSH directive ASH cannot honor end to end.
var ErrUnsupported = errors.New("unsupported OpenSSH configuration")

// maxOutput bounds the ssh -G result before parsing.
const maxOutput = 1 << 20

// Effective is the subset of resolved OpenSSH settings ASH consumes.
type Effective struct {
	HostName     string
	User         string
	Port         int
	Identities   []string
	AgentSocket  string
	HostKeyAlias string
	// KnownHostsFiles are UserKnownHostsFile candidates, in order. ssh -G
	// separates them with spaces, so paths containing spaces are unsupported.
	KnownHostsFiles []string
}

// Runner runs a command without a shell. It is a seam for tests.
type Runner func(ctx context.Context, name string, args ...string) ([]byte, error)

// Resolve runs the installed OpenSSH client to resolve an alias.
func Resolve(ctx context.Context, alias string) (Effective, error) {
	return resolve(ctx, alias, execRunner)
}

func execRunner(ctx context.Context, name string, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("%v: %s", err, strings.TrimSpace(stderr.String()))
	}
	if stdout.Len() > maxOutput {
		return nil, fmt.Errorf("ssh -G output exceeds %d bytes", maxOutput)
	}
	return stdout.Bytes(), nil
}

func resolve(ctx context.Context, alias string, runner Runner) (Effective, error) {
	if strings.TrimSpace(alias) == "" || strings.ContainsRune(alias, 0) {
		return Effective{}, fmt.Errorf("invalid OpenSSH alias %q", alias)
	}
	out, err := runner(ctx, "ssh", "-G", "--", alias)
	if err != nil {
		return Effective{}, fmt.Errorf("resolve OpenSSH alias %q: %w", alias, err)
	}
	effective, unsupported, err := parse(string(out))
	if err != nil {
		return Effective{}, err
	}
	if len(unsupported) > 0 {
		sort.Strings(unsupported)
		return Effective{}, fmt.Errorf("%w: alias %q uses %s, which ASH cannot honor", ErrUnsupported, alias, strings.Join(unsupported, ", "))
	}
	return effective, nil
}

func parse(out string) (Effective, []string, error) {
	effective := Effective{}
	unsupported := make([]string, 0)
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		key, value, ok := strings.Cut(line, " ")
		if !ok {
			continue
		}
		key = strings.ToLower(strings.TrimSpace(key))
		value = strings.TrimSpace(value)
		switch key {
		case "hostname":
			effective.HostName = value
		case "user":
			effective.User = value
		case "port":
			port, err := strconv.Atoi(value)
			if err != nil {
				return Effective{}, nil, fmt.Errorf("ssh -G returned invalid port %q", value)
			}
			effective.Port = port
		case "identityfile":
			if v := normalize(value); v != "" && v != "none" {
				effective.Identities = append(effective.Identities, v)
			}
		case "identityagent":
			switch v := normalize(value); strings.ToLower(v) {
			case "none":
				effective.AgentSocket = "none"
			case "ssh_auth_sock", "":
				// Empty means use the SSH_AUTH_SOCK environment variable.
			default:
				effective.AgentSocket = v
			}
		case "hostkeyalias":
			if value != "" {
				effective.HostKeyAlias = value
			}
		case "userknownhostsfile":
			if normalize(value) == "none" {
				// OpenSSH would then rely on global known_hosts files only,
				// which ASH does not read.
				unsupported = append(unsupported, "UserKnownHostsFile none")
			} else {
				effective.KnownHostsFiles = strings.Fields(value)
			}
		case "proxyjump":
			if v := normalize(value); v != "" && v != "none" {
				unsupported = append(unsupported, "ProxyJump")
			}
		case "proxycommand":
			if v := normalize(value); v != "" && v != "none" {
				unsupported = append(unsupported, "ProxyCommand")
			}
		case "certificatefile":
			if v := normalize(value); v != "" && v != "none" {
				unsupported = append(unsupported, "CertificateFile")
			}
		case "pkcs11provider":
			if v := normalize(value); v != "" && v != "none" {
				unsupported = append(unsupported, "PKCS11Provider")
			}
		}
	}
	return effective, unsupported, nil
}

func normalize(value string) string {
	if strings.EqualFold(value, "none") {
		return "none"
	}
	return value
}

// Apply merges effective OpenSSH values into an ASH host. Explicit ASH values
// win, then OpenSSH, then ASH defaults.
func (e Effective) Apply(h host.Host) host.Host {
	if strings.TrimSpace(h.Address) == "" {
		h.Address = e.HostName
	}
	if strings.TrimSpace(h.User) == "" {
		h.User = e.User
	}
	if h.Port == 0 {
		h.Port = e.Port
	}
	if h.Identity == "" && len(e.Identities) > 0 {
		h.Identities = append([]string(nil), e.Identities...)
	}
	h.AgentSocket = e.AgentSocket
	h.HostKeyAlias = e.HostKeyAlias
	h.KnownHostsFiles = append([]string(nil), e.KnownHostsFiles...)
	if h.Port == 0 {
		h.Port = 22
	}
	return h
}
