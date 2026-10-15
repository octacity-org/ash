package host

import (
	"errors"
	"fmt"
	"sort"

	"ash/internal/policy"
)

var ErrHostNotFound = errors.New("host not found")

type Host struct {
	Name         string        `toml:"-"`
	Address      string        `toml:"address"`
	Port         int           `toml:"port"`
	User         string        `toml:"user"`
	Identity     string        `toml:"identity"`
	SSHAlias     string        `toml:"ssh_alias"`
	ShellBackend string        `toml:"shell_backend"`
	Policy       policy.Policy `toml:"policy"`

	// Resolved from an OpenSSH alias at startup. They are never exposed through
	// `ash hosts` and are not part of the configuration file.
	Identities   []string `toml:"-"`
	AgentSocket  string   `toml:"-"`
	HostKeyAlias string   `toml:"-"`
	// KnownHostsFiles are the alias's UserKnownHostsFile candidates; empty
	// means the transport's default known_hosts file.
	KnownHostsFiles []string `toml:"-"`
}

type Registry struct{ hosts map[string]Host }

func New(hosts map[string]Host) *Registry {
	copyHosts := make(map[string]Host, len(hosts))
	for name, h := range hosts {
		h.Name = name
		copyHosts[name] = h
	}
	return &Registry{hosts: copyHosts}
}
func (r *Registry) Get(name string) (Host, error) {
	h, ok := r.hosts[name]
	if !ok {
		return Host{}, fmt.Errorf("%w: %q", ErrHostNotFound, name)
	}
	return h, nil
}
func (r *Registry) List() []Host {
	out := make([]Host, 0, len(r.hosts))
	for _, h := range r.hosts {
		out = append(out, h)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}
