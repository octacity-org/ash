package sshconfig

import (
	"context"
	"errors"
	"strings"
	"testing"

	"ash/internal/host"
	"ash/internal/policy"
)

func fakeRunner(output string, err error) Runner {
	return func(context.Context, string, ...string) ([]byte, error) {
		return []byte(output), err
	}
}

const fixture = `host alias
user ata
hostname 100.64.1.20
port 2222
identityfile ~/.ssh/id_ed25519
identityfile ~/.ssh/id_rsa
identityagent SSH_AUTH_SOCK
hostkeyalias hashed-name
proxycommand none
proxyjump none
certificatefile none
pkcs11provider none
`

func TestResolveParsesEffectiveFields(t *testing.T) {
	effective, err := resolve(context.Background(), "alias", fakeRunner(fixture, nil))
	if err != nil {
		t.Fatal(err)
	}
	if effective.HostName != "100.64.1.20" || effective.User != "ata" || effective.Port != 2222 {
		t.Fatalf("%+v", effective)
	}
	if len(effective.Identities) != 2 || effective.Identities[0] != "~/.ssh/id_ed25519" {
		t.Fatalf("%+v", effective)
	}
	if effective.AgentSocket != "" || effective.HostKeyAlias != "hashed-name" {
		t.Fatalf("%+v", effective)
	}
}

func TestResolveAgentAndUnsupportedDirectives(t *testing.T) {
	if effective, err := resolve(context.Background(), "a", fakeRunner("identityagent /run/agent.sock\n", nil)); err != nil || effective.AgentSocket != "/run/agent.sock" {
		t.Fatalf("%+v %v", effective, err)
	}
	if effective, err := resolve(context.Background(), "a", fakeRunner("identityagent none\n", nil)); err != nil || effective.AgentSocket != "none" {
		t.Fatalf("%+v %v", effective, err)
	}
	for directive, output := range map[string]string{
		"ProxyJump":               "proxyjump bastion\n",
		"ProxyCommand":            "proxycommand /usr/bin/nc %h %p\n",
		"CertificateFile":         "certificatefile ~/.ssh/id.crt\n",
		"PKCS11Provider":          "pkcs11provider /usr/lib/pkcs11.so\n",
		"UserKnownHostsFile none": "userknownhostsfile none\n",
	} {
		_, err := resolve(context.Background(), "a", fakeRunner(output, nil))
		if !errors.Is(err, ErrUnsupported) || !strings.Contains(err.Error(), directive) {
			t.Fatalf("%s: %v", directive, err)
		}
	}
}

func TestResolveKnownHostsFiles(t *testing.T) {
	effective, err := resolve(context.Background(), "a", fakeRunner("userknownhostsfile ~/.ssh/team_hosts /etc/ash/hosts\n", nil))
	if err != nil || strings.Join(effective.KnownHostsFiles, "|") != "~/.ssh/team_hosts|/etc/ash/hosts" {
		t.Fatalf("%+v %v", effective, err)
	}
	if applied := effective.Apply(host.Host{}); strings.Join(applied.KnownHostsFiles, "|") != "~/.ssh/team_hosts|/etc/ash/hosts" {
		t.Fatalf("%+v", applied)
	}
}

func TestResolveRejectsRunnerAndBadPort(t *testing.T) {
	if _, err := resolve(context.Background(), "a", fakeRunner("", errors.New("ssh: not found"))); err == nil {
		t.Fatal("accepted runner failure")
	}
	if _, err := resolve(context.Background(), "a", fakeRunner("port notanumber\n", nil)); err == nil {
		t.Fatal("accepted invalid port")
	}
	if _, err := resolve(context.Background(), "", fakeRunner(fixture, nil)); err == nil {
		t.Fatal("accepted empty alias")
	}
}

func TestApplyPrecedence(t *testing.T) {
	effective := Effective{HostName: "effective", User: "effuser", Port: 2200, Identities: []string{"~/.ssh/one"}, AgentSocket: "/run/sock", HostKeyAlias: "alias"}
	explicit := effective.Apply(host.Host{Address: "explicit", User: "exuser", Port: 2020, Identity: "~/.ssh/mine", Policy: policy.Policy{Exec: true}})
	if explicit.Address != "explicit" || explicit.User != "exuser" || explicit.Port != 2020 || explicit.Identity != "~/.ssh/mine" || len(explicit.Identities) != 0 {
		t.Fatalf("explicit values must win: %+v", explicit)
	}
	if explicit.AgentSocket != "/run/sock" || explicit.HostKeyAlias != "alias" {
		t.Fatalf("%+v", explicit)
	}
	sparse := effective.Apply(host.Host{})
	if sparse.Address != "effective" || sparse.User != "effuser" || sparse.Port != 2200 || len(sparse.Identities) != 1 {
		t.Fatalf("%+v", sparse)
	}
	noPort := Effective{HostName: "h", User: "u"}.Apply(host.Host{})
	if noPort.Port != 22 {
		t.Fatalf("%+v", noPort)
	}
}
