package service

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"ash/internal/audit"
	"ash/internal/host"
	"ash/internal/policy"
	"ash/internal/transport"
)

type fakeTransport struct {
	transport.Transport
	calls int
}

func (f *fakeTransport) Exec(context.Context, host.Host, transport.ExecRequest) (transport.ExecResult, error) {
	f.calls++
	return transport.ExecResult{ExitCode: 7}, nil
}
func (f *fakeTransport) Read(context.Context, host.Host, string) ([]byte, error) {
	f.calls++
	return []byte("hello"), nil
}
func (f *fakeTransport) Write(context.Context, host.Host, string, []byte) error {
	f.calls++
	return nil
}
func (f *fakeTransport) Stat(context.Context, host.Host, string) (transport.FileInfo, error) {
	f.calls++
	return transport.FileInfo{}, nil
}
func TestDeniedOperationsNeverReachTransport(t *testing.T) {
	f := new(fakeTransport)
	s := New(host.New(map[string]host.Host{"denied": {}}), f)
	ctx := context.Background()
	_, e1 := s.Exec(ctx, transport.ExecRequest{Host: "denied", Command: "true"})
	_, e2 := s.Read(ctx, "denied", "/x")
	e3 := s.Write(ctx, "denied", "/x", nil)
	_, e4 := s.Stat(ctx, "denied", "/x")
	_, e5 := s.List(ctx, "denied", "/x")
	e6 := s.Mkdir(ctx, "denied", "/x")
	e7 := s.Rename(ctx, "denied", "/x", "/y")
	e8 := s.Remove(ctx, "denied", "/x")
	e9 := s.AtomicWrite(ctx, "denied", "/x", nil)
	_, e10 := s.ReadTree(ctx, "denied", "/x")
	e11 := s.WriteTree(ctx, "denied", "/x", nil)
	for _, err := range []error{e1, e2, e3, e4, e5, e6, e7, e8, e9, e10, e11} {
		if !errors.Is(err, policy.ErrPermissionDenied) {
			t.Fatalf("got %v", err)
		}
	}
	if f.calls != 0 {
		t.Fatalf("transport called %d times", f.calls)
	}
	_, err := s.Exec(ctx, transport.ExecRequest{Host: "missing", Command: "true"})
	if !errors.Is(err, host.ErrHostNotFound) {
		t.Fatal(err)
	}
}
func TestExecNonzeroIsResultAndHostsHideCredentials(t *testing.T) {
	f := new(fakeTransport)
	s := New(host.New(map[string]host.Host{"allowed": {Identity: "secret", Policy: policy.Policy{Exec: true}}}), f)
	r, err := s.Exec(context.Background(), transport.ExecRequest{Host: "allowed", Command: "false"})
	if err != nil || r.ExitCode != 7 {
		t.Fatalf("%+v %v", r, err)
	}
	hs := s.Hosts()
	if len(hs) != 1 || len(hs[0].Capabilities) != 1 || hs[0].Capabilities[0] != "exec" {
		t.Fatalf("%+v", hs)
	}
}

func TestCanceledAndOversizedRequestsDoNotReachTransport(t *testing.T) {
	f := new(fakeTransport)
	s := New(host.New(map[string]host.Host{"h": {Policy: policy.Policy{Exec: true, Read: true, Write: true}}}), f)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, e1 := s.Exec(ctx, transport.ExecRequest{Host: "h", Command: "true"})
	_, e2 := s.Read(ctx, "h", "/x")
	e3 := s.Write(ctx, "h", "/x", nil)
	_, e4 := s.Stat(ctx, "h", "/x")
	for _, err := range []error{e1, e2, e3, e4} {
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("got %v", err)
		}
	}
	if err := s.Write(context.Background(), "h", "/x", make([]byte, transport.MaxWriteSize+1)); err == nil {
		t.Fatal("oversized write accepted")
	}
	if f.calls != 0 {
		t.Fatalf("transport called %d times", f.calls)
	}
}

type policyTransport struct {
	transport.Transport
	canonical   map[string]string
	execRequest transport.ExecRequest
	reads       int
	writes      int
}

func (f *policyTransport) Canonicalize(_ context.Context, _ host.Host, p string) (string, error) {
	if c, ok := f.canonical[p]; ok {
		return c, nil
	}
	return p, nil
}
func (f *policyTransport) Exec(_ context.Context, _ host.Host, req transport.ExecRequest) (transport.ExecResult, error) {
	f.execRequest = req
	return transport.ExecResult{}, nil
}
func (f *policyTransport) Read(context.Context, host.Host, string) ([]byte, error) {
	f.reads++
	return []byte("data"), nil
}
func (f *policyTransport) Mkdir(context.Context, host.Host, string) error {
	f.writes++
	return nil
}

func policyService(t *testing.T, f *policyTransport, pol policy.Policy) *Service {
	t.Helper()
	return New(host.New(map[string]host.Host{"h": {Policy: pol}}), f)
}

func TestShellBypassAndExecutableConstraints(t *testing.T) {
	f := new(policyTransport)
	s := policyService(t, f, policy.Policy{Exec: true, AllowedCommands: []string{"ls"}})
	ctx := context.Background()
	if _, err := s.Exec(ctx, transport.ExecRequest{Host: "h", Command: "ls -la"}); !errors.Is(err, policy.ErrPermissionDenied) {
		t.Fatalf("shell code with constraints: %v", err)
	}
	if _, err := s.Exec(ctx, transport.ExecRequest{Host: "h", Argv: []string{"rm", "-rf", "/"}}); !errors.Is(err, policy.ErrPermissionDenied) {
		t.Fatalf("disallowed executable: %v", err)
	}
	if _, err := s.Exec(ctx, transport.ExecRequest{Host: "h", Argv: []string{"ls", "-la"}}); err != nil {
		t.Fatal(err)
	}
	if len(f.execRequest.Argv) != 2 || f.execRequest.Argv[0] != "ls" {
		t.Fatalf("%+v", f.execRequest)
	}
	if _, err := s.Exec(ctx, transport.ExecRequest{Host: "h", Command: "true", Argv: []string{"ls"}}); err == nil {
		t.Fatal("accepted command and argv together")
	}
}

func TestExecCwdRoots(t *testing.T) {
	f := &policyTransport{canonical: map[string]string{"/etc": "/etc", "/work/x": "/work/x"}}
	s := policyService(t, f, policy.Policy{Exec: true, CwdRoots: []string{"/work"}})
	ctx := context.Background()
	if _, err := s.Exec(ctx, transport.ExecRequest{Host: "h", Command: "true", Cwd: "/etc"}); !errors.Is(err, policy.ErrPermissionDenied) {
		t.Fatalf("cwd outside roots: %v", err)
	}
	if _, err := s.Exec(ctx, transport.ExecRequest{Host: "h", Command: "true", Cwd: "/work/x"}); err != nil {
		t.Fatal(err)
	}
}

func TestReadRootsEnforcedBeforeTransport(t *testing.T) {
	f := &policyTransport{canonical: map[string]string{"/etc/passwd": "/etc/passwd", "/allowed/x": "/allowed/x"}}
	s := policyService(t, f, policy.Policy{Read: true, ReadRoots: []string{"/allowed"}})
	ctx := context.Background()
	if _, err := s.Read(ctx, "h", "/etc/passwd"); !errors.Is(err, policy.ErrPermissionDenied) {
		t.Fatalf("read outside roots: %v", err)
	}
	if f.reads != 0 {
		t.Fatal("denied read reached transport")
	}
	if _, err := s.Read(ctx, "h", "/allowed/x"); err != nil || f.reads != 1 {
		t.Fatalf("%v reads=%d", err, f.reads)
	}
}

func TestTimeoutAndOutputCaps(t *testing.T) {
	f := new(policyTransport)
	s := policyService(t, f, policy.Policy{Exec: true, MaxTimeoutSeconds: 60, MaxOutputBytes: 1024})
	if _, err := s.Exec(context.Background(), transport.ExecRequest{Host: "h", Command: "true", Timeout: 10 * time.Minute}); err != nil {
		t.Fatal(err)
	}
	if f.execRequest.Timeout > 60*time.Second {
		t.Fatalf("timeout not capped: %v", f.execRequest.Timeout)
	}
	if f.execRequest.MaxOutput != 1024 {
		t.Fatalf("output cap not applied: %d", f.execRequest.MaxOutput)
	}
}

func TestExecInputCapAndExpandedFileRoots(t *testing.T) {
	f := &policyTransport{canonical: map[string]string{"/denied": "/denied", "/allowed/new": "/allowed/new"}}
	s := policyService(t, f, policy.Policy{Exec: true, Write: true, MaxInputBytes: 2, WriteRoots: []string{"/allowed"}})
	if _, err := s.Exec(context.Background(), transport.ExecRequest{Host: "h", Command: "cat", Stdin: []byte("abc"), StdinSet: true}); !errors.Is(err, policy.ErrPermissionDenied) {
		t.Fatalf("oversized policy input: %v", err)
	}
	if f.execRequest.Command != "" {
		t.Fatal("denied input reached transport")
	}
	if err := s.Mkdir(context.Background(), "h", "/denied"); !errors.Is(err, policy.ErrPermissionDenied) {
		t.Fatalf("mkdir outside roots: %v", err)
	}
	if f.writes != 0 {
		t.Fatal("denied mkdir reached transport")
	}
	if err := s.Mkdir(context.Background(), "h", "/allowed/new"); err != nil || f.writes != 1 {
		t.Fatalf("allowed mkdir: %v writes=%d", err, f.writes)
	}
}

func TestAuditRecordsDeniedAndAllowed(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	recorder, err := audit.New(path)
	if err != nil {
		t.Fatal(err)
	}
	s := New(host.New(map[string]host.Host{"h": {Policy: policy.Policy{Exec: true}}, "denied": {}}), new(policyTransport))
	s.WithAudit(recorder)
	ctx := context.Background()
	if _, err := s.Exec(ctx, transport.ExecRequest{Host: "h", Command: "true"}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Exec(ctx, transport.ExecRequest{Host: "denied", Command: "true"}); err == nil {
		t.Fatal("denied exec accepted")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	text := string(data)
	if !strings.Contains(text, `"decision":"allowed"`) || !strings.Contains(text, `"decision":"denied"`) {
		t.Fatalf("audit missing decisions: %s", text)
	}
	if strings.Contains(text, "command") {
		t.Fatalf("audit leaked command: %s", text)
	}
}

type fileTransport struct {
	transport.Transport
	calls int
}

func (f *fileTransport) Mkdir(context.Context, host.Host, string) error { f.calls++; return nil }
func (f *fileTransport) WriteTree(_ context.Context, _ host.Host, _ string, _ []transport.TreeEntry) error {
	f.calls++
	return nil
}

func TestTreeOpsValidateBeforeTransport(t *testing.T) {
	f := new(fileTransport)
	s := New(host.New(map[string]host.Host{"h": {Policy: policy.Policy{Write: true}}}), f)
	if err := s.WriteTree(context.Background(), "h", "/remote", []transport.TreeEntry{{Path: "../escape", Data: []byte("x")}}); err == nil {
		t.Fatal("accepted unsafe tree")
	}
	if f.calls != 0 {
		t.Fatal("unsafe tree reached transport")
	}
	if err := s.Mkdir(context.Background(), "h", ""); err == nil {
		t.Fatal("accepted empty path")
	}
	if f.calls != 0 {
		t.Fatal("empty path reached transport")
	}
	if err := s.WriteTree(context.Background(), "h", "/remote", []transport.TreeEntry{{Path: "ok", Data: []byte("x")}}); err != nil || f.calls != 1 {
		t.Fatalf("%v calls=%d", err, f.calls)
	}
}

type execRecorder struct {
	transport.Transport
	request transport.ExecRequest
	reached bool
}

func (r *execRecorder) Exec(_ context.Context, _ host.Host, req transport.ExecRequest) (transport.ExecResult, error) {
	r.request = req
	r.reached = true
	return transport.ExecResult{}, nil
}

func TestExecStdinBoundAndEmptyDistinct(t *testing.T) {
	r := new(execRecorder)
	s := New(host.New(map[string]host.Host{"h": {Policy: policy.Policy{Exec: true}}}), r)
	ctx := context.Background()
	if _, err := s.Exec(ctx, transport.ExecRequest{Host: "h", Command: "cat", Stdin: make([]byte, transport.MaxExecInputSize+1), StdinSet: true}); err == nil {
		t.Fatal("oversized exec input accepted")
	}
	if r.reached {
		t.Fatal("oversized input reached transport")
	}
	if _, err := s.Exec(ctx, transport.ExecRequest{Host: "h", Command: "cat", StdinSet: true}); err != nil {
		t.Fatal(err)
	}
	if !r.request.StdinSet || len(r.request.Stdin) != 0 {
		t.Fatalf("empty stdin not distinguished: %+v", r.request)
	}
}

func TestTextAndWireTimeoutValidation(t *testing.T) {
	if _, err := Text([]byte{0xff}); err == nil {
		t.Fatal("invalid UTF-8 accepted")
	}
	for _, ms := range []int64{-1, 1<<63 - 1} {
		if _, err := TimeoutMillis(ms); err == nil {
			t.Fatalf("accepted %d", ms)
		}
	}
}

type usageTransport struct {
	transport.Transport
}

func (usageTransport) Exec(context.Context, host.Host, transport.ExecRequest) (transport.ExecResult, error) {
	return transport.ExecResult{Stdout: "1234", Stderr: "56", StderrTruncated: true}, nil
}
func (usageTransport) Read(context.Context, host.Host, string) ([]byte, error) {
	return []byte("hello"), nil
}
func (usageTransport) Write(context.Context, host.Host, string, []byte) error { return nil }
func (usageTransport) ReadTree(context.Context, host.Host, string) ([]transport.TreeEntry, error) {
	return []transport.TreeEntry{{Path: "d", IsDir: true}, {Path: "d/a", Data: []byte("abc")}}, nil
}

func auditRecords(t *testing.T, path string) []audit.Record {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var records []audit.Record
	for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		var r audit.Record
		if err := json.Unmarshal([]byte(line), &r); err != nil {
			t.Fatal(err)
		}
		records = append(records, r)
	}
	return records
}

func TestAuditRecordsByteCountsAndTruncation(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	recorder, err := audit.New(path)
	if err != nil {
		t.Fatal(err)
	}
	s := New(host.New(map[string]host.Host{"h": {Policy: policy.Policy{Exec: true, Read: true, Write: true}}}), usageTransport{}).WithAudit(recorder)
	ctx := context.Background()
	if _, err := s.Exec(ctx, transport.ExecRequest{Host: "h", Command: "cat", Stdin: []byte("abc"), StdinSet: true}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Read(ctx, "h", "/x"); err != nil {
		t.Fatal(err)
	}
	if err := s.Write(ctx, "h", "/x", []byte("1234567")); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ReadTree(ctx, "h", "/d"); err != nil {
		t.Fatal(err)
	}
	want := []audit.Record{
		{Operation: "exec", BytesIn: 3, BytesOut: 6, Truncated: true},
		{Operation: "read", BytesOut: 5},
		{Operation: "write", BytesIn: 7},
		{Operation: "download", BytesOut: 3},
	}
	got := auditRecords(t, path)
	if len(got) != len(want) {
		t.Fatalf("records: %+v", got)
	}
	for i, w := range want {
		g := got[i]
		if g.Operation != w.Operation || g.BytesIn != w.BytesIn || g.BytesOut != w.BytesOut || g.Truncated != w.Truncated {
			t.Fatalf("record %d = %+v, want %+v", i, g, w)
		}
	}
}

func TestHostsExposePolicyBounds(t *testing.T) {
	pol := policy.Policy{Exec: true, ReadRoots: []string{"/srv"}, CwdRoots: []string{"/work"}, AllowedCommands: []string{"git"}, AllowShell: true, MaxTimeoutSeconds: 60, MaxInputBytes: 1024, MaxOutputBytes: 2048, MaxStreamBytes: 4096}
	s := New(host.New(map[string]host.Host{"h": {Address: "a", User: "u", Identity: "secret", ShellBackend: "tmux", Policy: pol}, "plain": {Policy: policy.Policy{Read: true}}}), new(fakeTransport))
	data, err := json.Marshal(s.Hosts())
	if err != nil {
		t.Fatal(err)
	}
	text := string(data)
	for _, want := range []string{`"read_roots":["/srv"]`, `"cwd_roots":["/work"]`, `"allowed_commands":["git"]`, `"allow_shell":true`, `"max_timeout_seconds":60`, `"max_input_bytes":1024`, `"max_output_bytes":2048`, `"max_stream_bytes":4096`, `"shell_backend":"tmux"`} {
		if !strings.Contains(text, want) {
			t.Fatalf("missing %s in %s", want, text)
		}
	}
	if strings.Contains(text, "secret") || strings.Contains(text, "write_roots") {
		t.Fatalf("unexpected field in %s", text)
	}
	if plain := s.Hosts()[1]; plain.Name != "plain" || plain.ReadRoots != nil || plain.AllowShell {
		t.Fatalf("%+v", plain)
	}
}

type rangeTransport struct {
	transport.Transport
	offset, limit int64
}

func (r *rangeTransport) ReadRange(_ context.Context, _ host.Host, _ string, offset, limit int64) (transport.FileRange, error) {
	r.offset, r.limit = offset, limit
	return transport.FileRange{Data: []byte("abc"), Offset: 4, Size: 10}, nil
}

func TestReadRangeValidatesLimit(t *testing.T) {
	r := new(rangeTransport)
	s := New(host.New(map[string]host.Host{"h": {Policy: policy.Policy{Read: true}}, "denied": {}}), r)
	ctx := context.Background()
	for _, limit := range []int64{-1, transport.MaxReadSize + 1} {
		if _, err := s.ReadRange(ctx, "h", "/x", 0, limit); err == nil {
			t.Fatalf("accepted limit %d", limit)
		}
	}
	if _, err := s.ReadRange(ctx, "denied", "/x", 0, 1); !errors.Is(err, policy.ErrPermissionDenied) {
		t.Fatalf("denied: %v", err)
	}
	got, err := s.ReadRange(ctx, "h", "/x", -5, 0)
	if err != nil || string(got.Data) != "abc" || r.offset != -5 || r.limit != transport.MaxReadSize {
		t.Fatalf("%+v %v offset=%d limit=%d", got, err, r.offset, r.limit)
	}
}

func TestTextRangeDropsPartialCharacters(t *testing.T) {
	full := []byte("aé€b") // a, 2-byte é, 3-byte €, b
	// Starts inside é and ends inside €: both partial characters are dropped.
	text, offset, err := TextRange(transport.FileRange{Data: full[2:5], Offset: 2, Size: int64(len(full))})
	if err != nil || text != "" || offset != 3 {
		t.Fatalf("%q %d %v", text, offset, err)
	}
	text, offset, err = TextRange(transport.FileRange{Data: full[1:6], Offset: 1, Size: int64(len(full))})
	if err != nil || text != "é€" || offset != 1 {
		t.Fatalf("%q %d %v", text, offset, err)
	}
	// Invalid bytes inside the range are still rejected.
	if _, _, err := TextRange(transport.FileRange{Data: []byte{'a', 0xff, 'b'}, Size: 3}); err == nil {
		t.Fatal("binary accepted")
	}
}
