package service

import (
	"bytes"
	"context"
	"errors"
	"io"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"ash/internal/audit"
	"ash/internal/host"
	"ash/internal/policy"
	"ash/internal/transport"
)

// streamTransport echoes stdin to stdout, optionally after emitting chunks
// spaced by a delay, or blocks until cancellation when hang is set.
type streamTransport struct {
	transport.Transport
	canonical map[string]string
	calls     int
	request   transport.ExecRequest
	chunks    int
	every     time.Duration
	hang      bool
}

func (f *streamTransport) Canonicalize(_ context.Context, _ host.Host, p string) (string, error) {
	if c, ok := f.canonical[p]; ok {
		return c, nil
	}
	return p, nil
}

func (f *streamTransport) ExecStream(ctx context.Context, _ host.Host, req transport.ExecRequest, stdio transport.Stdio) (transport.ExecResult, error) {
	f.calls++
	f.request = req
	if f.hang {
		<-ctx.Done()
		return transport.ExecResult{}, ctx.Err()
	}
	for i := 0; i < f.chunks; i++ {
		select {
		case <-time.After(f.every):
		case <-ctx.Done():
			return transport.ExecResult{}, ctx.Err()
		}
		if _, err := stdio.Stdout.Write([]byte("tick\n")); err != nil {
			return transport.ExecResult{}, err
		}
	}
	if stdio.Stdin != nil {
		if _, err := io.Copy(stdio.Stdout, stdio.Stdin); err != nil {
			return transport.ExecResult{}, err
		}
	}
	if _, err := stdio.Stderr.Write([]byte("done")); err != nil {
		return transport.ExecResult{}, err
	}
	return transport.ExecResult{ExitCode: 3}, nil
}

func streamService(f *streamTransport, pol policy.Policy) *Service {
	return New(host.New(map[string]host.Host{"h": {Policy: pol}}), f)
}

func TestExecStreamPassesBytesBeyondBufferedCaps(t *testing.T) {
	f := new(streamTransport)
	s := streamService(f, policy.Policy{Exec: true, MaxInputBytes: 16, MaxOutputBytes: 16})
	input := bytes.Repeat([]byte("x"), transport.MaxOutputSize+1)
	var out, errout bytes.Buffer
	r, err := s.ExecStream(context.Background(), transport.ExecRequest{Host: "h", Command: "cat"}, transport.Stdio{Stdin: bytes.NewReader(input), Stdout: &out, Stderr: &errout})
	if err != nil || r.ExitCode != 3 {
		t.Fatalf("%+v %v", r, err)
	}
	if !bytes.Equal(out.Bytes(), input) || errout.String() != "done" {
		t.Fatalf("stdout %d bytes, stderr %q", out.Len(), errout.String())
	}
	if f.request.StdinSet || f.request.MaxOutput != 0 || f.request.Timeout != transport.DefaultExecTimeout {
		t.Fatalf("%+v", f.request)
	}
}

func TestExecStreamEnforcesExecPolicy(t *testing.T) {
	ctx := context.Background()
	stdio := transport.Stdio{Stdout: io.Discard, Stderr: io.Discard}
	f := &streamTransport{canonical: map[string]string{"/etc": "/etc"}}
	if _, err := streamService(f, policy.Policy{Read: true}).ExecStream(ctx, transport.ExecRequest{Host: "h", Command: "true"}, stdio); !errors.Is(err, policy.ErrPermissionDenied) {
		t.Fatalf("exec capability: %v", err)
	}
	constrained := streamService(f, policy.Policy{Exec: true, AllowedCommands: []string{"tar"}, CwdRoots: []string{"/work"}})
	if _, err := constrained.ExecStream(ctx, transport.ExecRequest{Host: "h", Command: "tar x"}, stdio); !errors.Is(err, policy.ErrPermissionDenied) {
		t.Fatalf("shell code: %v", err)
	}
	if _, err := constrained.ExecStream(ctx, transport.ExecRequest{Host: "h", Argv: []string{"rm"}}, stdio); !errors.Is(err, policy.ErrPermissionDenied) {
		t.Fatalf("executable: %v", err)
	}
	if _, err := constrained.ExecStream(ctx, transport.ExecRequest{Host: "h", Argv: []string{"tar"}, Cwd: "/etc"}, stdio); !errors.Is(err, policy.ErrPermissionDenied) {
		t.Fatalf("cwd: %v", err)
	}
	if f.calls != 0 {
		t.Fatalf("refused requests reached transport %d times", f.calls)
	}
	if _, err := constrained.ExecStream(ctx, transport.ExecRequest{Host: "h", Argv: []string{"tar"}, Cwd: "/work"}, stdio); err != nil || f.calls != 1 {
		t.Fatalf("allowed request: %v (%d calls)", err, f.calls)
	}
}

func TestExecStreamStopsAtByteLimit(t *testing.T) {
	f := new(streamTransport)
	s := streamService(f, policy.Policy{Exec: true, MaxStreamBytes: 64})
	var out bytes.Buffer
	_, err := s.ExecStream(context.Background(), transport.ExecRequest{Host: "h", Command: "cat"}, transport.Stdio{Stdin: strings.NewReader(strings.Repeat("y", 100)), Stdout: &out, Stderr: io.Discard})
	if !errors.Is(err, policy.ErrPermissionDenied) || !strings.Contains(err.Error(), "64 bytes") {
		t.Fatalf("%v", err)
	}
	if out.Len() != 0 {
		t.Fatalf("forwarded %d bytes past the limit", out.Len())
	}
}

func TestExecStreamTimeoutCountsInactivity(t *testing.T) {
	ctx := context.Background()
	stdio := transport.Stdio{Stdout: io.Discard, Stderr: io.Discard}
	// Steady output keeps a stream alive well past its timeout.
	busy := &streamTransport{chunks: 6, every: 30 * time.Millisecond}
	if _, err := streamService(busy, policy.Policy{Exec: true}).ExecStream(ctx, transport.ExecRequest{Host: "h", Command: "x", Timeout: 100 * time.Millisecond}, stdio); err != nil {
		t.Fatalf("active stream stopped: %v", err)
	}
	idle := &streamTransport{hang: true}
	started := time.Now()
	_, err := streamService(idle, policy.Policy{Exec: true}).ExecStream(ctx, transport.ExecRequest{Host: "h", Command: "x", Timeout: 50 * time.Millisecond}, stdio)
	if !errors.Is(err, transport.ErrTimeout) {
		t.Fatalf("%v", err)
	}
	if elapsed := time.Since(started); elapsed > 2*time.Second {
		t.Fatalf("idle stream stopped after %s", elapsed)
	}
	// The policy cap bounds the inactivity timeout too.
	capped := &streamTransport{hang: true}
	s := streamService(capped, policy.Policy{Exec: true, MaxTimeoutSeconds: 1})
	if _, err := s.ExecStream(ctx, transport.ExecRequest{Host: "h", Command: "x", Timeout: time.Hour}, stdio); !errors.Is(err, transport.ErrTimeout) || capped.request.Timeout != time.Second {
		t.Fatalf("%v %s", err, capped.request.Timeout)
	}
}

func TestExecStreamStopsWhenLocalOutputFails(t *testing.T) {
	f := new(streamTransport)
	s := streamService(f, policy.Policy{Exec: true})
	closed := errors.New("pipe closed")
	_, err := s.ExecStream(context.Background(), transport.ExecRequest{Host: "h", Command: "cat"}, transport.Stdio{Stdin: strings.NewReader("data"), Stdout: failingWriter{closed}, Stderr: io.Discard})
	if !errors.Is(err, closed) {
		t.Fatalf("%v", err)
	}
}

type failingWriter struct{ err error }

func (w failingWriter) Write([]byte) (int, error) { return 0, w.err }

func TestExecStreamAuditsMovedBytes(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	recorder, err := audit.New(path)
	if err != nil {
		t.Fatal(err)
	}
	s := streamService(new(streamTransport), policy.Policy{Exec: true, MaxStreamBytes: 20}).WithAudit(recorder)
	ctx := context.Background()
	if _, err := s.ExecStream(ctx, transport.ExecRequest{Host: "h", Command: "cat"}, transport.Stdio{Stdin: strings.NewReader("abc"), Stdout: io.Discard, Stderr: io.Discard}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ExecStream(ctx, transport.ExecRequest{Host: "h", Command: "cat"}, transport.Stdio{Stdin: strings.NewReader(strings.Repeat("z", 30)), Stdout: io.Discard, Stderr: io.Discard}); err == nil {
		t.Fatal("over-limit stream succeeded")
	}
	got := auditRecords(t, path)
	if len(got) != 2 {
		t.Fatalf("records: %+v", got)
	}
	// stdout echoes the 3 input bytes and stderr adds "done".
	if g := got[0]; g.Operation != "exec" || g.Result != audit.ResultOK || g.BytesIn != 3 || g.BytesOut != 7 {
		t.Fatalf("record 0 = %+v", g)
	}
	if g := got[1]; g.Result != audit.ResultError || g.BytesIn != 0 || g.BytesOut != 0 {
		t.Fatalf("record 1 = %+v", g)
	}
}
