package policy

import (
	"errors"
	"testing"
	"time"
)

func TestDefaultsPreserveBroadBehavior(t *testing.T) {
	p := Policy{Exec: true, Read: true, Write: true}
	if err := p.Validate(); err != nil {
		t.Fatal(err)
	}
	if err := p.Check("exec"); err != nil {
		t.Fatal(err)
	}
	if err := p.CheckShell(); err != nil {
		t.Fatal(err)
	}
	if err := p.CheckExecutable("/any/binary"); err != nil {
		t.Fatal(err)
	}
	if err := p.CheckRoots("/etc/passwd", false); err != nil {
		t.Fatal(err)
	}
	if p.MaxTimeout() != 0 {
		t.Fatal("unexpected default timeout")
	}
}

func TestValidateRootsAndBounds(t *testing.T) {
	for name, p := range map[string]Policy{
		"relative root": {ReadRoots: []string{"relative"}},
		"unclean root":  {WriteRoots: []string{"/a/../b"}},
		"nul root":      {CwdRoots: []string{"/a\x00"}},
		"timeout bound": {MaxTimeoutSeconds: HardMaxTimeoutSeconds + 1},
		"input bound":   {MaxInputBytes: HardMaxInputBytes + 1},
		"output bound":  {MaxOutputBytes: HardMaxOutputBytes + 1},
		"stream bound":  {MaxStreamBytes: -1},
		"no port":       {ForwardTargets: []string{"localhost"}},
		"zero port":     {ForwardTargets: []string{"localhost:0"}},
		"empty host":    {ForwardTargets: []string{":3000"}},
		"empty command": {AllowedCommands: []string{""}},
	} {
		if err := p.Validate(); err == nil {
			t.Fatalf("%s accepted", name)
		}
	}
	if err := (Policy{ReadRoots: []string{"/var/log"}, MaxTimeoutSeconds: 30}).Validate(); err != nil {
		t.Fatal(err)
	}
}

func TestCommandConstraintRejectsShellCode(t *testing.T) {
	p := Policy{Exec: true, AllowedCommands: []string{"ls", "cat"}}
	if err := p.CheckShell(); !errors.Is(err, ErrPermissionDenied) {
		t.Fatalf("shell code accepted: %v", err)
	}
	if err := p.CheckExecutable("ls"); err != nil {
		t.Fatal(err)
	}
	if err := p.CheckExecutable("/bin/cat"); err != nil {
		t.Fatal(err)
	}
	if err := p.CheckExecutable("rm"); !errors.Is(err, ErrPermissionDenied) {
		t.Fatalf("unexpected executable accepted: %v", err)
	}
	allowed := p
	allowed.AllowShell = true
	if err := allowed.CheckShell(); err != nil {
		t.Fatal(err)
	}
}

func TestRootBoundaries(t *testing.T) {
	p := Policy{ReadRoots: []string{"/data"}, WriteRoots: []string{"/work"}}
	if err := p.CheckRoots("/data", false); err != nil {
		t.Fatal(err)
	}
	if err := p.CheckRoots("/data/inner/file", false); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{"/database", "/data2", "/etc", "/data/../etc"} {
		if err := p.CheckRoots(path, false); !errors.Is(err, ErrPermissionDenied) {
			t.Fatalf("%s: accepted", path)
		}
	}
	// Read roots do not grant write access.
	if err := p.CheckRoots("/data/file", true); !errors.Is(err, ErrPermissionDenied) {
		t.Fatal("write outside write roots accepted")
	}
	if err := p.CheckCwd("/work"); err != nil {
		// No cwd roots configured means unconstrained.
		t.Fatal(err)
	}
	if err := (Policy{CwdRoots: []string{"/work"}}).CheckCwd("/etc"); !errors.Is(err, ErrPermissionDenied) {
		t.Fatal("cwd outside roots accepted")
	}
}

func TestRootSlashAllowsEverythingUnderRoot(t *testing.T) {
	p := Policy{ReadRoots: []string{"/"}, WriteRoots: []string{"/"}}
	for _, path := range []string{"/", "/etc/passwd", "/data/inner/file"} {
		if err := p.CheckRoots(path, false); err != nil {
			t.Fatalf("read %s: %v", path, err)
		}
		if err := p.CheckRoots(path, true); err != nil {
			t.Fatalf("write %s: %v", path, err)
		}
	}
	if err := (Policy{CwdRoots: []string{"/"}}).CheckCwd("/etc"); err != nil {
		t.Fatal(err)
	}
}

func TestCheckExecutablePathEntriesAreExact(t *testing.T) {
	p := Policy{AllowedCommands: []string{"/usr/bin/git", "grep"}}
	// Exact path matches are accepted.
	if err := p.CheckExecutable("/usr/bin/git"); err != nil {
		t.Fatal(err)
	}
	// A same-named binary elsewhere must NOT inherit the /usr/bin allowlist.
	if err := p.CheckExecutable("/tmp/git"); err == nil {
		t.Fatal("/tmp/git accepted via /usr/bin/git basename match")
	}
	// A bare entry matches the basename wherever it resides.
	if err := p.CheckExecutable("/usr/bin/grep"); err != nil {
		t.Fatal(err)
	}
	if err := p.CheckExecutable("/opt/bin/grep"); err != nil {
		t.Fatal(err)
	}
	// Unrelated programs are still rejected.
	if err := p.CheckExecutable("/usr/bin/curl"); err == nil {
		t.Fatal("curl accepted")
	}
}

func TestBounds(t *testing.T) {
	p := Policy{MaxTimeoutSeconds: 45, MaxInputBytes: 10, MaxOutputBytes: 20}
	if p.MaxTimeout() != 45*time.Second {
		t.Fatalf("%v", p.MaxTimeout())
	}
	if err := p.CheckInput(11); !errors.Is(err, ErrPermissionDenied) {
		t.Fatal("oversized input accepted")
	}
	if err := p.CheckInput(10); err != nil {
		t.Fatal(err)
	}
	if err := p.CheckOutput(21); !errors.Is(err, ErrPermissionDenied) {
		t.Fatal("oversized output accepted")
	}
}

func TestForwardCapabilityAndTargets(t *testing.T) {
	if err := (Policy{Exec: true}).Check("forward"); !errors.Is(err, ErrPermissionDenied) {
		t.Fatalf("forward allowed without capability: %v", err)
	}
	p := Policy{Forward: true, ForwardTargets: []string{"localhost:3000", "[::1]:5432"}}
	if err := p.Validate(); err != nil {
		t.Fatal(err)
	}
	if err := p.Check("forward"); err != nil {
		t.Fatal(err)
	}
	for _, target := range []string{"localhost:3000", "[::1]:5432"} {
		if err := p.CheckForwardTarget(target); err != nil {
			t.Fatalf("%s: %v", target, err)
		}
	}
	for _, target := range []string{"127.0.0.1:3000", "localhost:3001", "db:5432"} {
		if err := p.CheckForwardTarget(target); !errors.Is(err, ErrPermissionDenied) {
			t.Fatalf("%s allowed: %v", target, err)
		}
	}
	if err := (Policy{Forward: true}).CheckForwardTarget("anything:1"); err != nil {
		t.Fatalf("empty forward_targets must be unconstrained: %v", err)
	}
}
