package config

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/pelletier/go-toml/v2"

	"ash/internal/host"
)

var hostName = regexp.MustCompile(`^[A-Za-z0-9_-]+$`)

// AddHost appends a minimal host entry to the configuration file. It refuses to
// touch an existing host name or an unparseable file so a user's configuration
// is never silently rewritten.
func AddHost(path, name string, h host.Host) (bool, error) {
	if !hostName.MatchString(name) {
		return false, fmt.Errorf("host name %q must contain only letters, digits, hyphen or underscore", name)
	}
	existing, err := os.ReadFile(path)
	if err != nil && !os.IsNotExist(err) {
		return false, fmt.Errorf("read config %q: %w", path, err)
	}
	if len(existing) > 0 {
		parsed, err := Parse(existing)
		if err != nil {
			return false, fmt.Errorf("refusing to modify an invalid config: %w", err)
		}
		if _, ok := parsed.Hosts[name]; ok {
			return false, fmt.Errorf("host %q already exists in %s", name, path)
		}
	}
	body, err := toml.Marshal(struct {
		Address      string `toml:"address,omitempty"`
		Port         int    `toml:"port,omitempty"`
		User         string `toml:"user,omitempty"`
		Identity     string `toml:"identity,omitempty"`
		SSHAlias     string `toml:"ssh_alias,omitempty"`
		ShellBackend string `toml:"shell_backend,omitempty"`
	}{Address: h.Address, Port: h.Port, User: h.User, Identity: h.Identity, SSHAlias: h.SSHAlias, ShellBackend: h.ShellBackend})
	if err != nil {
		return false, err
	}
	policyBody, err := toml.Marshal(h.Policy)
	if err != nil {
		return false, err
	}
	block := "[hosts." + name + "]\n" + string(body) + "[hosts." + name + ".policy]\n" + string(policyBody)
	content := block
	if len(existing) > 0 {
		content = strings.TrimRight(string(existing), "\n") + "\n\n" + block
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return false, fmt.Errorf("create config directory: %w", err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		return false, fmt.Errorf("write config %q: %w", path, err)
	}
	return true, nil
}
