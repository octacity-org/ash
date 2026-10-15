package integration

import (
	"ash/internal/sshconfig"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
)

// TestOpenSSHAliasResolution exercises the real ssh -G path, including Include
// and Match. It is opt-in because it requires the OpenSSH client.
func TestOpenSSHAliasResolution(t *testing.T) {
	if os.Getenv("ASH_INTEGRATION") != "1" {
		t.Skip("set ASH_INTEGRATION=1 to run real OpenSSH alias resolution")
	}
	if runtime.GOOS == "windows" {
		t.Skip("the ssh wrapper is a POSIX shell script")
	}
	realSSH, err := exec.LookPath("ssh")
	if err != nil {
		t.Skip("OpenSSH client not installed")
	}
	dir := t.TempDir()
	extra := filepath.Join(dir, "extra.conf")
	if err := os.WriteFile(extra, []byte("Host include-target\n  HostName include.example\n  User includeuser\n  Port 2200\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	// Include is absolute: with -F, relative includes still resolve against
	// the real ~/.ssh.
	config := filepath.Join(dir, "config")
	body := "Include " + extra + "\n" +
		"Host alias\n  HostName alias.example\n  User aliasuser\n  IdentityFile ~/.ssh/id_one\n  IdentityFile ~/.ssh/id_two\n" +
		"Match originalhost alias\n  Port 2222\n"
	if err := os.WriteFile(config, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	// OpenSSH finds ~/.ssh/config through the passwd entry, not HOME, so a
	// wrapper earlier on PATH pins the configuration while Resolve still runs
	// the real client.
	bin := filepath.Join(dir, "bin")
	if err := os.Mkdir(bin, 0o700); err != nil {
		t.Fatal(err)
	}
	wrapper := "#!/bin/sh\nexec '" + realSSH + "' -F '" + config + "' \"$@\"\n"
	if err := os.WriteFile(filepath.Join(bin, "ssh"), []byte(wrapper), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
	effective, err := sshconfig.Resolve(context.Background(), "alias")
	if err != nil {
		t.Fatal(err)
	}
	if effective.HostName != "alias.example" || effective.User != "aliasuser" || effective.Port != 2222 {
		t.Fatalf("%+v", effective)
	}
	if len(effective.Identities) != 2 {
		t.Fatalf("identities: %+v", effective)
	}
	included, err := sshconfig.Resolve(context.Background(), "include-target")
	if err != nil || included.HostName != "include.example" || included.User != "includeuser" || included.Port != 2200 {
		t.Fatalf("%+v %v", included, err)
	}
}
