package ssh

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"net"
	"os"
	"path/filepath"
	"testing"

	"ash/internal/host"
	"ash/internal/transport"

	gossh "golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

// 64-byte ed25519 private seed (two 32-byte halves), the smallest valid
// representation gossh.ParsePrivateKey accepts in OpenSSH PEM form.
var testKeyPEM = `-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
QyNTUxOQAAACBBYmNkZWZnaGlqa2xtbm9wcXJzdHV2d3h5ejAxMjM0NTYAAAAIbmlzdHA1
MTIAAAEFFwAAAAtzc2gtZWQyNTUxOQAAAEBBYmNkZWZnaGlqa2xtbm9wcXJzdHV2d3h5ej
AxMjM0NTY=
-----END OPENSSH PRIVATE KEY-----
`

func TestSelectIdentitiesExplicitStaysStrict(t *testing.T) {
	h := host.Host{Identity: "~/.ssh/id_ed25519"}
	paths, explicit := selectIdentities(h)
	if !explicit {
		t.Fatal("explicit ASH identity must be marked strict")
	}
	if len(paths) != 1 || paths[0] != "~/.ssh/id_ed25519" {
		t.Fatalf("unexpected paths %v", paths)
	}
}

func TestSelectIdentitiesResolvedAreLenient(t *testing.T) {
	h := host.Host{Identities: []string{"~/.ssh/id_rsa", "~/.ssh/id_ed25519"}}
	paths, explicit := selectIdentities(h)
	if explicit {
		t.Fatal("ssh -G resolved identities must not be strict")
	}
	if len(paths) != 2 {
		t.Fatalf("unexpected paths %v", paths)
	}
}

func TestLoadIdentityFileSkipsMissingWhenAllowed(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "id_rsa")
	if _, err := loadIdentityFile(missing, true); !errors.Is(err, errIdentityMissing) {
		t.Fatalf("missingOK=true should yield errIdentityMissing, got %v", err)
	}
	if _, err := loadIdentityFile(missing, false); err == nil || errors.Is(err, errIdentityMissing) {
		t.Fatalf("missingOK=false must fail strictly, got %v", err)
	}
}

func TestLoadIdentityFileRejectsGarbage(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "id_bad")
	if err := os.WriteFile(path, []byte("not a key"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadIdentityFile(path, true); err == nil || errors.Is(err, errIdentityMissing) {
		t.Fatalf("unparseable key must be an error, got %v", err)
	}
}

// Alias hosts verify against the known_hosts files OpenSSH resolved for them,
// skipping candidates that do not exist, and never share pooled connections
// with hosts that trust different files.
func TestKnownHostsFilesFromAlias(t *testing.T) {
	dir := t.TempDir()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	key, err := gossh.NewPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	trusted := filepath.Join(dir, "team_hosts")
	line := knownhosts.Line([]string{knownhosts.Normalize("box.example:22")}, key)
	if err := os.WriteFile(trusted, []byte(line+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	tr, err := New(filepath.Join(dir, "default_known_hosts"))
	if err != nil {
		t.Fatal(err)
	}
	defer tr.Close()
	remote := &net.TCPAddr{IP: net.IPv4(192, 0, 2, 1), Port: 22}
	alias := host.Host{Name: "box", Address: "box.example", Port: 22, KnownHostsFiles: []string{filepath.Join(dir, "missing"), trusted}}
	callback, err := tr.knownHosts(alias)
	if err != nil {
		t.Fatal(err)
	}
	if err := callback("box.example:22", remote, key); err != nil {
		t.Fatalf("alias trust file not used: %v", err)
	}
	if _, err := tr.knownHosts(host.Host{Name: "plain", Address: "box.example", Port: 22}); !errors.Is(err, transport.ErrHostKey) {
		t.Fatalf("default trust file is missing, got %v", err)
	}
	if _, err := tr.knownHosts(host.Host{Name: "none", KnownHostsFiles: []string{filepath.Join(dir, "missing")}}); !errors.Is(err, transport.ErrHostKey) {
		t.Fatalf("no existing trust file, got %v", err)
	}
	plain := alias
	plain.KnownHostsFiles = nil
	if keyFor(alias, tr.knownHostsPath) == keyFor(plain, tr.knownHostsPath) {
		t.Fatal("hosts with different trust files share a pool key")
	}
}
