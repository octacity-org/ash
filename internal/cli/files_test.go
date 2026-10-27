package cli

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"ash/internal/host"
	"ash/internal/policy"
	"ash/internal/service"
	"ash/internal/transport"
)

type downloadTransport struct {
	fileTransport
}

// TestDownloadRefusesSymlinkedDestinationComponent pins the fix for writing
// outside the local root when an existing directory component is a symlink.
func TestDownloadRefusesSymlinkedDestinationComponent(t *testing.T) {
	local := t.TempDir()
	outside := t.TempDir()
	escape := filepath.Join(local, "out")
	if err := os.Symlink(outside, escape); err != nil {
		if strings.Contains(err.Error(), "symlink") && strings.Contains(err.Error(), "privilege") {
			t.Skip("symlink creation not permitted")
		}
		t.Fatal(err)
	}
	f := &fileTransport{readTree: []transport.TreeEntry{{Path: "out/secret.txt", Data: []byte("pwn")}}}
	s := service.New(host.New(map[string]host.Host{"h": {Policy: policy.Policy{Read: true, Write: true}}}), f)
	err := runDownload(context.Background(), []string{"h", "/remote", local}, s)
	if err == nil {
		t.Fatal("download through a symlinked destination directory must fail")
	}
	if !strings.Contains(err.Error(), "symlink") {
		t.Fatalf("unexpected error: %v", err)
	}
	// Nothing may have been written through the symlink.
	if _, err := os.Stat(filepath.Join(outside, "secret.txt")); !os.IsNotExist(err) {
		t.Fatalf("file escaped the download root: %v", err)
	}
}

// A pre-existing symlink at the exact file destination is also refused.
func TestDownloadRefusesSymlinkedFileTarget(t *testing.T) {
	local := t.TempDir()
	outside := t.TempDir()
	if err := os.MkdirAll(filepath.Join(local, "sub"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(outside, "victim.txt"), []byte("original"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(outside, "victim.txt"), filepath.Join(local, "sub", "x.txt")); err != nil {
		t.Fatal(err)
	}
	f := &fileTransport{readTree: []transport.TreeEntry{{Path: "sub/x.txt", Data: []byte("pwn")}}}
	s := service.New(host.New(map[string]host.Host{"h": {Policy: policy.Policy{Read: true, Write: true}}}), f)
	if err := runDownload(context.Background(), []string{"h", "/remote", local}, s); err == nil {
		t.Fatal("download over a symlinked file target must fail")
	}
	data, err := os.ReadFile(filepath.Join(outside, "victim.txt"))
	if err != nil || string(data) != "original" {
		t.Fatalf("symlink target was overwritten: %q %v", data, err)
	}
}

// The benign path keeps working: normal trees download unchanged.
func TestDownloadNormalTreeStillWorks(t *testing.T) {
	local := t.TempDir()
	f := &fileTransport{readTree: []transport.TreeEntry{
		{Path: "sub", IsDir: true},
		{Path: "sub/x.txt", Data: []byte("hi")},
		{Path: "top.txt", Data: []byte("top")},
	}}
	s := service.New(host.New(map[string]host.Host{"h": {Policy: policy.Policy{Read: true, Write: true}}}), f)
	if err := runDownload(context.Background(), []string{"h", "/remote", local}, s); err != nil {
		t.Fatal(err)
	}
	if data, err := os.ReadFile(filepath.Join(local, "sub", "x.txt")); err != nil || string(data) != "hi" {
		t.Fatalf("nested file: %q %v", data, err)
	}
	if data, err := os.ReadFile(filepath.Join(local, "top.txt")); err != nil || string(data) != "top" {
		t.Fatalf("top file: %q %v", data, err)
	}
}

// A download into a missing destination root must create the root (including
// its missing ancestors) instead of failing on the first child.
func TestDownloadCreatesMissingDestinationRoot(t *testing.T) {
	base := t.TempDir()
	local := filepath.Join(base, "new", "nested", "root")
	f := &fileTransport{readTree: []transport.TreeEntry{
		{Path: "top.txt", Data: []byte("top")},
		{Path: "sub", IsDir: true},
		{Path: "sub/x.txt", Data: []byte("hi")},
	}}
	s := service.New(host.New(map[string]host.Host{"h": {Policy: policy.Policy{Read: true, Write: true}}}), f)
	if err := runDownload(context.Background(), []string{"h", "/remote", local}, s); err != nil {
		t.Fatalf("download into missing root: %v", err)
	}
	if data, err := os.ReadFile(filepath.Join(local, "top.txt")); err != nil || string(data) != "top" {
		t.Fatalf("top file: %q %v", data, err)
	}
	if data, err := os.ReadFile(filepath.Join(local, "sub", "x.txt")); err != nil || string(data) != "hi" {
		t.Fatalf("nested file: %q %v", data, err)
	}
	// Only the destination tree was created, nothing beside it.
	entries, err := os.ReadDir(filepath.Join(base, "new", "nested"))
	if err != nil || len(entries) != 1 || entries[0].Name() != "root" {
		t.Fatalf("unexpected sibling entries: %+v %v", entries, err)
	}
}

// An existing normal root keeps working (regression guard for root creation).
func TestDownloadExistingRootStillWorks(t *testing.T) {
	local := filepath.Join(t.TempDir(), "existing")
	if err := os.MkdirAll(local, 0o755); err != nil {
		t.Fatal(err)
	}
	f := &fileTransport{readTree: []transport.TreeEntry{{Path: "x.txt", Data: []byte("x")}}}
	s := service.New(host.New(map[string]host.Host{"h": {Policy: policy.Policy{Read: true, Write: true}}}), f)
	if err := runDownload(context.Background(), []string{"h", "/remote", local}, s); err != nil {
		t.Fatal(err)
	}
	if data, err := os.ReadFile(filepath.Join(local, "x.txt")); err != nil || string(data) != "x" {
		t.Fatalf("file: %q %v", data, err)
	}
}

// A symlinked destination root is rejected even though the root is now
// created when missing: existing symlinks are never traversed.
func TestDownloadRefusesSymlinkedDestinationRoot(t *testing.T) {
	base := t.TempDir()
	outside := t.TempDir()
	escape := filepath.Join(base, "out")
	if err := os.Symlink(outside, escape); err != nil {
		if strings.Contains(err.Error(), "symlink") && strings.Contains(err.Error(), "privilege") {
			t.Skip("symlink creation not permitted")
		}
		t.Fatal(err)
	}
	f := &fileTransport{readTree: []transport.TreeEntry{{Path: "secret.txt", Data: []byte("pwn")}}}
	s := service.New(host.New(map[string]host.Host{"h": {Policy: policy.Policy{Read: true, Write: true}}}), f)
	if err := runDownload(context.Background(), []string{"h", "/remote", escape}, s); err == nil {
		t.Fatal("download into a symlinked root must fail")
	} else if !strings.Contains(err.Error(), "symlink") {
		t.Fatalf("unexpected error: %v", err)
	}
	if _, err := os.Stat(filepath.Join(outside, "secret.txt")); !os.IsNotExist(err) {
		t.Fatalf("file escaped the download root: %v", err)
	}
}

// Creating a missing root must not open a loophole: a symlinked ancestor of
// the new root is still refused, so nothing is created beyond the symlink.
func TestDownloadRefusesSymlinkedAncestorOfNewRoot(t *testing.T) {
	base := t.TempDir()
	outside := t.TempDir()
	if err := os.Symlink(outside, filepath.Join(base, "out")); err != nil {
		if strings.Contains(err.Error(), "symlink") && strings.Contains(err.Error(), "privilege") {
			t.Skip("symlink creation not permitted")
		}
		t.Fatal(err)
	}
	newRoot := filepath.Join(base, "out", "fresh")
	f := &fileTransport{readTree: []transport.TreeEntry{{Path: "secret.txt", Data: []byte("pwn")}}}
	s := service.New(host.New(map[string]host.Host{"h": {Policy: policy.Policy{Read: true, Write: true}}}), f)
	if err := runDownload(context.Background(), []string{"h", "/remote", newRoot}, s); err == nil {
		t.Fatal("download through a symlinked ancestor must fail")
	}
	if _, err := os.Stat(filepath.Join(outside, "fresh")); !os.IsNotExist(err) {
		t.Fatalf("directory was created beyond the symlink: %v", err)
	}
	if _, err := os.Stat(filepath.Join(outside, "secret.txt")); !os.IsNotExist(err) {
		t.Fatalf("file escaped the download root: %v", err)
	}
}

// Downloads apply the remote permission bits, and uploads send the local
// ones, so executable scripts survive a round trip.
func TestTreeTransfersKeepPermissionBits(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX permission bits")
	}
	local := t.TempDir()
	f := &fileTransport{readTree: []transport.TreeEntry{
		{Path: "run.sh", Data: []byte("#!/bin/sh\n"), Perm: 0o755},
		{Path: "secret", Data: []byte("s"), Perm: 0o600},
		{Path: "plain", Data: []byte("p")},
	}}
	s := service.New(host.New(map[string]host.Host{"h": {Policy: policy.Policy{Read: true, Write: true}}}), f)
	if err := runDownload(context.Background(), []string{"h", "/remote", local}, s); err != nil {
		t.Fatal(err)
	}
	want := map[string]os.FileMode{"run.sh": 0o755, "secret": 0o600, "plain": 0o644}
	for name, mode := range want {
		info, err := os.Stat(filepath.Join(local, name))
		if err != nil || info.Mode().Perm() != mode {
			t.Fatalf("%s downloaded as %v, want %v (%v)", name, info.Mode().Perm(), mode, err)
		}
	}
	if err := runUpload(context.Background(), []string{"h", local, "/remote"}, s); err != nil {
		t.Fatal(err)
	}
	for _, entry := range f.writeTree {
		if entry.Perm != want[entry.Path] {
			t.Fatalf("%s uploaded as %v, want %v", entry.Path, entry.Perm, want[entry.Path])
		}
	}
}
