package cli

import (
	"bytes"
	"context"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"ash/internal/config"
	"ash/internal/doctor"
	"ash/internal/host"
	"ash/internal/policy"
	"ash/internal/service"
	"ash/internal/shell"
	"ash/internal/transport"
)

type recorder struct {
	transport.Transport
	request transport.ExecRequest
}

func (r *recorder) Exec(_ context.Context, _ host.Host, req transport.ExecRequest) (transport.ExecResult, error) {
	r.request = req
	return transport.ExecResult{ExitCode: 9, Stdout: "out", Stderr: "err"}, nil
}
func TestExecPreservesCommandAndExit(t *testing.T) {
	r := new(recorder)
	s := service.New(host.New(map[string]host.Host{"h": {Policy: policy.Policy{Exec: true}}}), r)
	var out, errout bytes.Buffer
	code := Run(context.Background(), []string{"exec", "h", "--cwd", "~/a b", "--env", "X=a=b", "--timeout", "2s", "--", "printf '%s' \"$X\"; exit 9"}, s, nil, strings.NewReader(""), &out, &errout)
	if code != 9 || out.String() != "out" || errout.String() != "err" {
		t.Fatalf("%d %q %q", code, out.String(), errout.String())
	}
	if r.request.Command != "printf '%s' \"$X\"; exit 9" || r.request.Cwd != "~/a b" || r.request.Env["X"] != "a=b" {
		t.Fatalf("%+v", r.request)
	}
}
func TestExecvUsesArgv(t *testing.T) {
	r := new(recorder)
	s := service.New(host.New(map[string]host.Host{"h": {Policy: policy.Policy{Exec: true}}}), r)
	var out, errout bytes.Buffer
	code := Run(context.Background(), []string{"execv", "h", "--", "printf", "%s", "a b"}, s, nil, strings.NewReader(""), &out, &errout)
	if code != 9 {
		t.Fatalf("%d %q", code, errout.String())
	}
	if len(r.request.Argv) != 3 || r.request.Argv[0] != "printf" || r.request.Argv[2] != "a b" || r.request.Command != "" {
		t.Fatalf("%+v", r.request)
	}
	if code := Run(context.Background(), []string{"execv", "h", "true"}, s, nil, strings.NewReader(""), &out, &errout); code != 1 {
		t.Fatal("accepted execv without delimiter")
	}
}

func TestExecRequiresDelimiter(t *testing.T) {
	var out bytes.Buffer
	if c := Run(context.Background(), []string{"exec", "h", "true"}, nil, nil, strings.NewReader(""), &out, &out); c != 1 {
		t.Fatal(c)
	}
}

type fileTransport struct {
	transport.Transport
	atomicData []byte
	list       []transport.DirEntry
	readTree   []transport.TreeEntry
	writeRoot  string
	writeTree  []transport.TreeEntry
	rangeArgs  [2]int64
	readData   []byte
	streamed   []byte
	atomic     bool
}

func (f *fileTransport) ReadStream(_ context.Context, _ host.Host, _ string, w io.Writer) error {
	_, err := w.Write(f.readData)
	return err
}
func (f *fileTransport) WriteStream(_ context.Context, _ host.Host, _ string, r io.Reader, atomic bool) error {
	data, err := io.ReadAll(r)
	f.streamed, f.atomic = data, atomic
	return err
}

func (f *fileTransport) List(context.Context, host.Host, string) ([]transport.DirEntry, error) {
	return f.list, nil
}
func (f *fileTransport) ReadRange(_ context.Context, _ host.Host, _ string, offset, limit int64) (transport.FileRange, error) {
	f.rangeArgs = [2]int64{offset, limit}
	return transport.FileRange{Data: []byte("slice"), Offset: 3, Size: 9}, nil
}
func (f *fileTransport) Mkdir(context.Context, host.Host, string) error          { return nil }
func (f *fileTransport) Rename(context.Context, host.Host, string, string) error { return nil }
func (f *fileTransport) Remove(context.Context, host.Host, string) error         { return nil }
func (f *fileTransport) AtomicWrite(_ context.Context, _ host.Host, _ string, data []byte) error {
	f.atomicData = data
	return nil
}
func (f *fileTransport) ReadTree(context.Context, host.Host, string) ([]transport.TreeEntry, error) {
	return f.readTree, nil
}
func (f *fileTransport) WriteTree(_ context.Context, _ host.Host, root string, entries []transport.TreeEntry) error {
	f.writeRoot = root
	f.writeTree = entries
	return nil
}

func TestFileCLIOperations(t *testing.T) {
	f := &fileTransport{list: []transport.DirEntry{{Name: "a", IsDir: false}}}
	s := service.New(host.New(map[string]host.Host{"h": {Policy: policy.Policy{Read: true, Write: true}}}), f)
	var out, errout bytes.Buffer
	run := func(args ...string) int {
		out.Reset()
		errout.Reset()
		return Run(context.Background(), args, s, nil, strings.NewReader(""), &out, &errout)
	}
	if code := run("list", "h", "/d"); code != 0 || !strings.Contains(out.String(), `"name":"a"`) {
		t.Fatalf("list: %d %q %q", code, out.String(), errout.String())
	}
	if code := Run(context.Background(), []string{"write", "h", "/p", "--atomic"}, s, nil, strings.NewReader("data"), &out, &errout); code != 0 || string(f.streamed) != "data" || !f.atomic {
		t.Fatalf("atomic write: %d %q %v", code, f.streamed, f.atomic)
	}
	large := strings.Repeat("w", transport.MaxWriteSize+1)
	if code := Run(context.Background(), []string{"write", "h", "/p"}, s, nil, strings.NewReader(large), &out, &errout); code != 0 || len(f.streamed) != len(large) || f.atomic {
		t.Fatalf("large write: %d %d %v %q", code, len(f.streamed), f.atomic, errout.String())
	}
	f.readData = []byte(large)
	if code := run("read", "h", "/big"); code != 0 || out.Len() != len(large) {
		t.Fatalf("large read: %d %d %q", code, out.Len(), errout.String())
	}
	if code := run("read", "h", "/log", "--offset", "-6", "--limit=4"); code != 0 || out.String() != "slice" || f.rangeArgs != [2]int64{-6, 4} {
		t.Fatalf("read range: %d %q %q %v", code, out.String(), errout.String(), f.rangeArgs)
	}
	if code := run("read", "h", "/log", "--offset", "x"); code != 1 {
		t.Fatalf("bad offset accepted: %d", code)
	}
	if code := run("mkdir", "h", "/d"); code != 0 || !strings.Contains(out.String(), `"ok":true`) {
		t.Fatalf("mkdir: %d %q", code, out.String())
	}
	if code := run("rename", "h", "/a", "/b"); code != 0 {
		t.Fatalf("rename: %d %q", code, errout.String())
	}
	if code := run("remove", "h", "/a"); code != 0 {
		t.Fatalf("remove: %d %q", code, errout.String())
	}

	local := t.TempDir()
	f.readTree = []transport.TreeEntry{{Path: "sub", IsDir: true}, {Path: "sub/x.txt", Data: []byte("hi")}, {Path: "top.txt", Data: []byte("top")}}
	if code := run("download", "h", "/remote", local); code != 0 {
		t.Fatalf("download: %d %q", code, errout.String())
	}
	if data, err := os.ReadFile(filepath.Join(local, "sub", "x.txt")); err != nil || string(data) != "hi" {
		t.Fatalf("downloaded %q %v", data, err)
	}
	if data, err := os.ReadFile(filepath.Join(local, "top.txt")); err != nil || string(data) != "top" {
		t.Fatalf("downloaded top %q %v", data, err)
	}

	upload := t.TempDir()
	if err := os.MkdirAll(filepath.Join(upload, "nested"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(upload, "nested", "y.txt"), []byte("yo"), 0o644); err != nil {
		t.Fatal(err)
	}
	if code := run("upload", "h", upload, "/remote"); code != 0 {
		t.Fatalf("upload: %d %q", code, errout.String())
	}
	if f.writeRoot != "/remote" {
		t.Fatalf("root %q", f.writeRoot)
	}
	found := false
	for _, entry := range f.writeTree {
		if entry.Path == "nested/y.txt" && string(entry.Data) == "yo" {
			found = true
		}
	}
	if !found {
		t.Fatalf("upload entries %+v", f.writeTree)
	}
}

func TestHostAddCommand(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.toml")
	var out, errout bytes.Buffer
	if code := HostAdd([]string{"fedora", "--address", "10.0.0.1", "--user", "ata", "--exec"}, path, &out, &errout); code != 0 || !strings.Contains(out.String(), `"host":"fedora"`) {
		t.Fatalf("%d %q %q", code, out.String(), errout.String())
	}
	c, err := config.Load(path)
	if err != nil || !c.Hosts["fedora"].Policy.Exec || c.Hosts["fedora"].User != "ata" {
		t.Fatalf("%v %+v", err, c.Hosts)
	}
	if code := HostAdd([]string{"bad", "--user", "u"}, path, &out, &errout); code != 1 {
		t.Fatal("missing address accepted")
	}
	if code := HostAdd([]string{"box", "--ssh-alias", "my-server", "--shell-backend=tmux", "--read"}, path, &out, &errout); code != 0 {
		t.Fatalf("%d %q", code, errout.String())
	}
	c, err = config.Load(path)
	if box := c.Hosts["box"]; err != nil || box.SSHAlias != "my-server" || box.ShellBackend != "tmux" || box.Port != 0 || box.Address != "" || !box.Policy.Read {
		t.Fatalf("%v %+v", err, box)
	}
	if code := HostAdd([]string{"bad", "--ssh-alias", "x", "--shell-backend", "screen"}, path, &out, &errout); code != 1 {
		t.Fatal("unknown shell backend accepted")
	}
}

type doctorTransport struct{ transport.Transport }

func (doctorTransport) Exec(context.Context, host.Host, transport.ExecRequest) (transport.ExecResult, error) {
	return transport.ExecResult{}, nil
}

func TestDoctorCommandTextAndJSON(t *testing.T) {
	known := filepath.Join(t.TempDir(), "known_hosts")
	d := doctor.New(host.New(map[string]host.Host{"h": {Address: "a", Port: 22, User: "u", Policy: policy.Policy{Exec: true}}}), doctorTransport{}, known)
	var out, errout bytes.Buffer
	if code := Doctor(context.Background(), []string{"h"}, d, &out, &errout); code != 0 || !strings.Contains(out.String(), "trust") || !strings.Contains(out.String(), "host key verified") {
		t.Fatalf("%d %q %q", code, out.String(), errout.String())
	}
	out.Reset()
	if code := Doctor(context.Background(), []string{"h", "--json"}, d, &out, &errout); code != 0 || !strings.HasPrefix(strings.TrimSpace(out.String()), "{") {
		t.Fatalf("%d %q", code, out.String())
	}
	if code := Doctor(context.Background(), []string{"missing"}, d, &out, &errout); code != 1 {
		t.Fatal("unknown host should fail")
	}
}

func TestSetupCommandParsing(t *testing.T) {
	var out, errout bytes.Buffer
	if code := Setup(nil, "/usr/bin/ash", "/tmp/config.toml", &out, &errout); code != 0 || !strings.Contains(out.String(), "codex") || !strings.Contains(out.String(), "freebuff") {
		t.Fatalf("%d %q %q", code, out.String(), errout.String())
	}
	out.Reset()
	errout.Reset()
	if code := Setup([]string{"claude"}, "/usr/bin/ash", "/tmp/config.toml", &out, &errout); code != 1 || !strings.Contains(errout.String(), "Manual configuration example") {
		t.Fatalf("%d %q", code, errout.String())
	}
}

func TestExecStdinFlag(t *testing.T) {
	r := new(recorder)
	s := service.New(host.New(map[string]host.Host{"h": {Policy: policy.Policy{Exec: true}}}), r)
	var out, errout bytes.Buffer
	code := Run(context.Background(), []string{"exec", "h", "--stdin", "--", "cat"}, s, nil, strings.NewReader("payload"), &out, &errout)
	if code != 9 || string(r.request.Stdin) != "payload" || !r.request.StdinSet {
		t.Fatalf("%d %+v %q", code, r.request, errout.String())
	}
	// Without --stdin, input is neither consumed nor forwarded.
	r.request = transport.ExecRequest{}
	code = Run(context.Background(), []string{"exec", "h", "--", "true"}, s, nil, strings.NewReader("ignored"), &out, &errout)
	if code != 9 || r.request.StdinSet || r.request.Stdin != nil {
		t.Fatalf("%d %+v", code, r.request)
	}
	// Oversized input fails clearly before reaching the transport.
	r.request = transport.ExecRequest{}
	code = Run(context.Background(), []string{"exec", "h", "--stdin", "--", "cat"}, s, nil, strings.NewReader(strings.Repeat("x", transport.MaxExecInputSize+1)), &out, &errout)
	if code != 1 || r.request.StdinSet || !strings.Contains(errout.String(), "input exceeds") {
		t.Fatalf("%d %+v %q", code, r.request, errout.String())
	}
}

func TestWriteCancellationInterruptsStdin(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	reader, writer := io.Pipe()
	defer reader.Close()
	defer writer.Close()
	var out, errout bytes.Buffer
	done := make(chan int, 1)
	s := service.New(host.New(map[string]host.Host{"h": {Policy: policy.Policy{Write: true}}}), new(fileTransport))
	go func() { done <- Run(ctx, []string{"write", "h", "/x"}, s, nil, reader, &out, &errout) }()
	cancel()
	select {
	case code := <-done:
		if code != 1 {
			t.Fatal(code)
		}
	case <-time.After(time.Second):
		t.Fatal("write remained blocked on stdin after cancellation")
	}
}

type shellRecorder struct {
	shell.Backend
	input, cwd, id, cursor string
}

func (r *shellRecorder) Name() string { return "test" }
func (r *shellRecorder) Create(_ context.Context, _ host.Host, id, cwd string) error {
	r.cwd = cwd
	r.id = id
	return nil
}
func (r *shellRecorder) Send(_ context.Context, _ host.Host, id, input string) error {
	r.input = input
	return nil
}
func TestShellCLI(t *testing.T) {
	r := new(shellRecorder)
	shells := service.NewShells(host.New(map[string]host.Host{"h": {Policy: policy.Policy{Exec: true}}}), r)
	var out, errout bytes.Buffer
	code := Run(context.Background(), []string{"shell", "create", "h", "--cwd", "~/a b"}, nil, shells, strings.NewReader(""), &out, &errout)
	if code != 0 || r.cwd != "~/a b" || !strings.Contains(out.String(), `"id":"sh_`) {
		t.Fatalf("%d %q %q", code, out.String(), errout.String())
	}
	id := "sh_" + strings.Repeat("a", 32)
	code = Run(context.Background(), []string{"shell", "send", "h", id}, nil, shells, strings.NewReader("pwd\n"), &out, &errout)
	if code != 0 || r.input != "pwd\n" {
		t.Fatalf("%d %q %q", code, r.input, errout.String())
	}
	code = Run(context.Background(), []string{"shell", "send", "h", id, "--", "-literal"}, nil, shells, strings.NewReader("unused"), &out, &errout)
	if code != 0 || r.input != "-literal" {
		t.Fatalf("%d %q", code, r.input)
	}
}

func (r *shellRecorder) List(context.Context, host.Host) ([]string, error) {
	if r.id == "" {
		return []string{}, nil
	}
	return []string{r.id}, nil
}
func (r *shellRecorder) Read(_ context.Context, _ host.Host, _ string, req shell.ReadRequest) (shell.Output, error) {
	r.cursor = req.Cursor
	return shell.Output{Content: r.input, Cursor: "next-cursor", Truncated: true}, nil
}
func (r *shellRecorder) Close(context.Context, host.Host, string) error { r.id = ""; return nil }
func TestShellCLIListReadCloseAndInputLimit(t *testing.T) {
	id := "sh_" + strings.Repeat("b", 32)
	r := &shellRecorder{id: id, input: "captured output"}
	shells := service.NewShells(host.New(map[string]host.Host{"h": {Policy: policy.Policy{Exec: true}}}), r)
	var out, errout bytes.Buffer
	run := func(args ...string) int {
		out.Reset()
		errout.Reset()
		return Run(context.Background(), args, nil, shells, strings.NewReader(""), &out, &errout)
	}
	if code := run("shell", "list", "h"); code != 0 || !strings.Contains(out.String(), id) {
		t.Fatalf("%d %q %q", code, out.String(), errout.String())
	}
	if code := run("shell", "read", "h", id); code != 0 || out.String() != "captured output" || !strings.Contains(errout.String(), "truncated") {
		t.Fatalf("%d %q %q", code, out.String(), errout.String())
	}
	if code := run("shell", "read", "h", id, "--cursor", "abc", "--json"); code != 0 || r.cursor != "abc" || !strings.Contains(out.String(), `"cursor":"next-cursor"`) {
		t.Fatalf("%d %q %q", code, out.String(), errout.String())
	}
	if code := run("shell", "wait", "h", id, "--until", "captured", "--timeout", "1s", "--json"); code != 0 || !strings.Contains(out.String(), `"matched":true`) {
		t.Fatalf("%d %q %q", code, out.String(), errout.String())
	}
	if code := run("shell", "wait", "h", id, "--until", "a", "--regex", "b"); code != 1 {
		t.Fatal("accepted both matchers")
	}
	if code := Run(context.Background(), []string{"shell", "send", "h", id}, nil, shells, strings.NewReader(strings.Repeat("a", shell.MaxInputSize+1)), &out, &errout); code != 1 || r.input != "captured output" {
		t.Fatalf("%d input mutated", code)
	}
	if code := run("shell", "close", "h", id); code != 0 || r.id != "" {
		t.Fatalf("%d %q", code, r.id)
	}
	if code := run("shell", "list", "h"); code != 0 || out.String() != "[]\n" {
		t.Fatalf("%d %q", code, out.String())
	}
}
