package ssh

import (
	"ash/internal/host"
	"ash/internal/transport"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/pkg/sftp"
)

// sftpFixture serves an in-process SFTP server (github.com/pkg/sftp) over
// direct pipes, so AtomicWrite runs against real sftp.Client semantics -
// including the posix-rename@openssh.com round trip - without any network or
// configured host. The transport's SFTP dial is replaced by the fixture.
//
// The server's working directory is pinned to the fixture root and every test
// addresses files with POSIX-style *relative* remote paths, mirroring how
// production code handles remote paths (and derives temporary paths with
// POSIX path.Dir). Relative paths keep the client- and server-side spelling
// identical on every platform: on Windows an absolute POSIX path would be
// reinterpreted against a drive ("cannot move the file to a different disk
// drive"), while a relative path always resolves into the single temporary
// root and can never cross drives.
type sftpFixture struct {
	tr   *Transport
	h    host.Host
	root string
}

func newSFTPFixture(t *testing.T) *sftpFixture {
	t.Helper()
	dir := t.TempDir()

	tr, err := New(filepath.Join(dir, "known_hosts"))
	if err != nil {
		t.Fatal(err)
	}

	cr, serverWrite := io.Pipe() // client reads what the server writes
	serverRead, cw := io.Pipe()  // server reads what the client writes
	server, err := sftp.NewServer(struct {
		io.Reader
		io.WriteCloser
	}{serverRead, serverWrite}, sftp.WithServerWorkingDirectory(dir))
	if err != nil {
		t.Fatal(err)
	}
	go server.Serve()

	// The client never dials: sftp.NewClientPipe connects straight to the
	// in-process server, exercising genuine client-side extension handling.
	client, err := sftp.NewClientPipe(cr, cw)
	if err != nil {
		t.Fatal(err)
	}
	// Closing the pipes unblocks the client's receive loop, so the pipes
	// must close before the client or its Close would wait forever.
	t.Cleanup(func() {
		cw.Close()
		cr.Close()
		server.Close()
		client.Close()
	})

	tr.newSFTPDial = func(ctx context.Context, h host.Host) (*sftp.Client, func(), error) {
		return client, func() {}, nil
	}

	h := host.Host{Name: "fixture", Address: "127.0.0.1", Port: 0, User: "u"}
	return &sftpFixture{tr: tr, h: h, root: dir}
}

// sftpFor returns the fixture's SFTP client (the same instance the transport
// hands to the code under test) for out-of-band inspection.
func (f *sftpFixture) sftpFor(t *testing.T) *sftp.Client {
	t.Helper()
	fs, cleanup, err := f.tr.files(context.Background(), f.h)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(cleanup)
	return fs
}

// Atomic write must create a missing file and replace an existing one through
// posix-rename, via the production Transport code path. The in-process server
// serves the real filesystem, so tests run inside a unique temp directory.
func TestAtomicWriteCreatesAndReplacesOverSFTP(t *testing.T) {
	f := newSFTPFixture(t)
	ctx := context.Background()
	// Relative POSIX remote path, resolved by the server against its working
	// directory (the fixture root) on every platform.
	target := "atomic-create-replace.txt"

	if err := f.tr.AtomicWrite(ctx, f.h, target, []byte("first")); err != nil {
		t.Fatal(err)
	}
	assertSFTPContent(t, f, target, "first")

	if err := f.tr.AtomicWrite(ctx, f.h, target, []byte("second")); err != nil {
		t.Fatalf("replacement over existing file failed: %v", err)
	}
	assertSFTPContent(t, f, target, "second")
}

// A failed replacement must leave the previous destination intact and clean
// up the temporary file. The rename target is a directory, so the final
// posix rename fails after the temp file is fully written.
func TestAtomicWriteFailureKeepsOldDestinationAndCleansTemp(t *testing.T) {
	f := newSFTPFixture(t)
	ctx := context.Background()
	target := "atomic-keep-old.txt"

	if err := f.tr.Mkdir(ctx, f.h, target); err != nil {
		t.Fatal(err)
	}
	if err := f.tr.AtomicWrite(ctx, f.h, target, []byte("replacement")); err == nil {
		t.Fatal("atomic write over a directory must fail")
	}
	// The destination directory still exists and no temp file remains.
	fs := f.sftpFor(t)
	if info, err := fs.Stat(target); err != nil || !info.IsDir() {
		t.Fatalf("destination altered by failed write: %v", err)
	}
	assertNoTempFiles(t, fs, f.root)
}

// A server without the posix-rename extension must yield a clear
// unsupported-operation error rather than a silent non-atomic fallback, and
// it must never delete the destination to work around the missing extension.
func TestAtomicWriteWithoutPosixRenameExtensionIsUnsupported(t *testing.T) {
	if !isUnsupportedOperation(&sftp.StatusError{Code: uint32(sftp.ErrSSHFxOpUnsupported)}) {
		t.Fatal("SSH_FX_OP_UNSUPPORTED status must be detected")
	}
	if isUnsupportedOperation(&sftp.StatusError{Code: uint32(sftp.ErrSSHFxFailure)}) {
		t.Fatal("SSH_FX_FAILURE must not be treated as unsupported")
	}
	if isUnsupportedOperation(errors.New("some transport error")) {
		t.Fatal("plain errors must not be treated as unsupported")
	}

	// The helper derives the temporary path with POSIX path.Dir, so the
	// destination must be a POSIX-style path too. Chdir into a unique
	// directory and use a relative path: on Windows a drive-letter destination
	// would make path.Dir degenerate to "." and leak the temp file into the
	// package working directory.
	dir := t.TempDir()
	t.Chdir(dir)
	destination := "config.txt"
	if err := os.WriteFile(destination, []byte("keep me"), 0o644); err != nil {
		t.Fatal(err)
	}
	removed := 0
	fs := &legacyServer{
		destination: destination,
		removed:     &removed,
	}
	err := atomicWriteSFTP(fs, destination, []byte("new bytes"))
	if err == nil || !isUnsupportedOperation(err) || !strings.Contains(err.Error(), "posix-rename@openssh.com") {
		t.Fatalf("expected clear unsupported error, got %v", err)
	}
	if removed != 1 {
		t.Fatalf("temp file must still be cleaned up, Remove called %d times", removed)
	}
	// The old destination must be intact: no delete-then-rename workaround.
	data, readErr := os.ReadFile(destination)
	if readErr != nil || string(data) != "keep me" {
		t.Fatalf("destination altered: %q %v", data, readErr)
	}
}

// legacyServer simulates an SFTP server that predates the posix-rename
// extension: writing a real temp file works, but every rename answers
// SSH_FX_OP_UNSUPPORTED and nothing is ever unlinked server-side.
type legacyServer struct {
	destination string
	removed     *int
}

func (l *legacyServer) OpenFile(path string, f int) (sftpFile, error) {
	return os.OpenFile(path, f, 0o644)
}

func (l *legacyServer) PosixRename(oldname, newname string) error {
	return &sftp.StatusError{Code: uint32(sftp.ErrSSHFxOpUnsupported)}
}

func (l *legacyServer) Stat(path string) (os.FileInfo, error) { return os.Stat(path) }

func (l *legacyServer) Remove(path string) error {
	*l.removed++
	return os.Remove(path)
}

// Renaming over an existing file through the in-process server matches
// POSIX semantics, proving the fixture supports what AtomicWrite needs.
func TestPosixRenameReplacesExisting(t *testing.T) {
	f := newSFTPFixture(t)
	a, b := "posix-a.txt", "posix-b.txt"
	if err := f.tr.Write(context.Background(), f.h, a, []byte("A")); err != nil {
		t.Fatal(err)
	}
	if err := f.tr.Write(context.Background(), f.h, b, []byte("BBBB")); err != nil {
		t.Fatal(err)
	}
	fs := f.sftpFor(t)
	if err := fs.PosixRename(a, b); err != nil {
		t.Fatalf("posix rename: %v", err)
	}
	if _, err := fs.Stat(a); !os.IsNotExist(err) {
		t.Fatalf("source should be gone: %v", err)
	}
	assertSFTPContent(t, f, b, "A")
}

func assertSFTPContent(t *testing.T, f *sftpFixture, path, want string) {
	t.Helper()
	fs := f.sftpFor(t)
	got, err := fs.Open(path)
	if err != nil {
		t.Fatalf("open %s: %v", path, err)
	}
	defer got.Close()
	data, err := io.ReadAll(got)
	if err != nil || string(data) != want {
		t.Fatalf("content of %s = %q err %v, want %q", path, data, err, want)
	}
}

func assertNoTempFiles(t *testing.T, fs *sftp.Client, dir string) {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if len(e.Name()) > 9 && e.Name()[:9] == ".ash-tmp-" {
			t.Fatalf("temporary file left behind: %s", e.Name())
		}
	}
}

// Atomic replacement keeps the destination's permission bits so edits never
// strip an executable bit or widen a private file; new files get 0644.
func TestAtomicWritePreservesExistingMode(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX permission bits")
	}
	f := newSFTPFixture(t)
	ctx := context.Background()
	for name, mode := range map[string]os.FileMode{"script.sh": 0o755, "secret.txt": 0o600} {
		local := filepath.Join(f.root, name)
		if err := os.WriteFile(local, []byte("old"), mode); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(local, mode); err != nil {
			t.Fatal(err)
		}
		if err := f.tr.AtomicWrite(ctx, f.h, name, []byte("new")); err != nil {
			t.Fatal(err)
		}
		info, err := os.Stat(local)
		if err != nil || info.Mode().Perm() != mode {
			t.Fatalf("%s mode = %v, want %v (%v)", name, info.Mode().Perm(), mode, err)
		}
	}
	if err := f.tr.AtomicWrite(ctx, f.h, "fresh.txt", []byte("new")); err != nil {
		t.Fatal(err)
	}
	if info, err := os.Stat(filepath.Join(f.root, "fresh.txt")); err != nil || info.Mode().Perm() != 0o644 {
		t.Fatalf("new file mode = %v (%v)", info.Mode().Perm(), err)
	}
}

// Tree transfers carry permission bits both ways, so scripts stay executable;
// entries without a mode keep the 0644 default.
func TestTreeTransfersKeepPermissionBits(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX permission bits")
	}
	f := newSFTPFixture(t)
	ctx := context.Background()
	entries := []transport.TreeEntry{
		{Path: "run.sh", Data: []byte("#!/bin/sh\n"), Perm: 0o755},
		{Path: "secret", Data: []byte("s"), Perm: 0o600},
		{Path: "plain", Data: []byte("p")},
	}
	if err := f.tr.WriteTree(ctx, f.h, "modes", entries); err != nil {
		t.Fatal(err)
	}
	want := map[string]os.FileMode{"run.sh": 0o755, "secret": 0o600, "plain": 0o644}
	for name, mode := range want {
		info, err := os.Stat(filepath.Join(f.root, "modes", name))
		if err != nil || info.Mode().Perm() != mode {
			t.Fatalf("%s written as %v, want %v (%v)", name, info.Mode().Perm(), mode, err)
		}
	}
	read, err := f.tr.ReadTree(ctx, f.h, "modes")
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range read {
		if entry.Perm != want[entry.Path] {
			t.Fatalf("%s read as %v, want %v", entry.Path, entry.Perm, want[entry.Path])
		}
	}
}

// Ranged reads seek instead of loading the whole file, so they work past the
// whole-file read limit; a negative offset counts back from the end.
func TestReadRangeSlicesAndTails(t *testing.T) {
	f := newSFTPFixture(t)
	ctx := context.Background()
	if err := os.WriteFile(filepath.Join(f.root, "digits"), []byte("0123456789"), 0o644); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		offset, limit int64
		data          string
		start         int64
	}{
		{2, 3, "234", 2},
		{-3, 10, "789", 7},
		{-100, 4, "0123", 0},
		{20, 4, "", 10},
	} {
		r, err := f.tr.ReadRange(ctx, f.h, "digits", tc.offset, tc.limit)
		if err != nil || string(r.Data) != tc.data || r.Offset != tc.start || r.Size != 10 {
			t.Fatalf("offset %d limit %d: %+v %v", tc.offset, tc.limit, r, err)
		}
	}
	big := make([]byte, transport.MaxReadSize+10)
	copy(big[len(big)-4:], "tail")
	if err := os.WriteFile(filepath.Join(f.root, "big"), big, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := f.tr.Read(ctx, f.h, "big"); !errors.Is(err, transport.ErrTooLarge) {
		t.Fatalf("whole read: %v", err)
	}
	r, err := f.tr.ReadRange(ctx, f.h, "big", -4, transport.MaxReadSize)
	if err != nil || string(r.Data) != "tail" {
		t.Fatalf("%q %v", r.Data, err)
	}
}
