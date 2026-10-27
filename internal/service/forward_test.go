package service

import (
	"context"
	"errors"
	"io"
	"net"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"ash/internal/audit"
	"ash/internal/host"
	"ash/internal/policy"
	"ash/internal/transport"
)

// echoServer accepts connections and echoes each one until its peer closes
// its write side.
func echoServer(t *testing.T) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { listener.Close() })
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func() {
				io.Copy(conn, conn)
				conn.Close()
			}()
		}
	}()
	return listener.Addr().String()
}

// forwardTransport hands out a forwarder that reaches echo instead of the
// requested target and records what was asked of it.
type forwardTransport struct {
	transport.Transport
	echo    string
	opened  int
	closed  int
	mu      sync.Mutex
	targets []string
}

func (f *forwardTransport) Forward(context.Context, host.Host) (transport.Forwarder, error) {
	f.opened++
	return fakeForwarder{f}, nil
}

type fakeForwarder struct{ f *forwardTransport }

func (d fakeForwarder) Dial(ctx context.Context, address string) (net.Conn, error) {
	d.f.mu.Lock()
	d.f.targets = append(d.f.targets, address)
	d.f.mu.Unlock()
	return (&net.Dialer{}).DialContext(ctx, "tcp", d.f.echo)
}

func (d fakeForwarder) Close() error {
	d.f.closed++
	return nil
}

func TestForwardServesTargetUntilCancelled(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	recorder, err := audit.New(path)
	if err != nil {
		t.Fatal(err)
	}
	f := &forwardTransport{echo: echoServer(t)}
	s := New(host.New(map[string]host.Host{"h": {Policy: policy.Policy{Forward: true, ForwardTargets: []string{"localhost:3000"}}}}), f).WithAudit(recorder)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ready := make(chan net.Addr, 1)
	done := make(chan error, 1)
	go func() { done <- s.Forward(ctx, "h", 0, "localhost:3000", func(addr net.Addr) { ready <- addr }) }()
	var addr net.Addr
	select {
	case addr = <-ready:
	case err := <-done:
		t.Fatal(err)
	}
	if ip := addr.(*net.TCPAddr).IP; !ip.IsLoopback() {
		t.Fatalf("listening on %s", addr)
	}

	conn, err := net.Dial("tcp", addr.String())
	if err != nil {
		t.Fatal(err)
	}
	conn.Write([]byte("ping"))
	conn.(*net.TCPConn).CloseWrite()
	reply, err := io.ReadAll(conn)
	conn.Close()
	if err != nil || string(reply) != "ping" {
		t.Fatalf("%q %v", reply, err)
	}

	// An open connection must not keep Forward running after cancellation.
	open, err := net.Dial("tcp", addr.String())
	if err != nil {
		t.Fatal(err)
	}
	defer open.Close()
	open.Write([]byte("x"))
	if _, err := io.ReadFull(open, make([]byte, 1)); err != nil {
		t.Fatal(err)
	}
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("forward kept running after cancellation")
	}
	open.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := open.Read(make([]byte, 1)); err == nil {
		t.Fatal("forwarded connection stayed open after shutdown")
	}
	if _, err := net.Dial("tcp", addr.String()); err == nil {
		t.Fatal("listener stayed open after shutdown")
	}
	if f.opened != 1 || f.closed != 1 || len(f.targets) != 2 || f.targets[0] != "localhost:3000" {
		t.Fatalf("opened %d closed %d targets %v", f.opened, f.closed, f.targets)
	}

	records := auditRecords(t, path)
	if len(records) != 2 {
		t.Fatalf("records: %+v", records)
	}
	found := false
	for _, r := range records {
		if r.Operation != "forward" || r.Target != "localhost:3000" || r.Result != audit.ResultOK {
			t.Fatalf("record %+v", r)
		}
		found = found || (r.BytesIn == 4 && r.BytesOut == 4)
	}
	if !found {
		t.Fatalf("no record carries the 4 forwarded bytes: %+v", records)
	}
}

func TestForwardRefusalsNeverConnect(t *testing.T) {
	f := new(forwardTransport)
	s := New(host.New(map[string]host.Host{
		"off":     {Policy: policy.Policy{Exec: true}},
		"limited": {Policy: policy.Policy{Forward: true, ForwardTargets: []string{"localhost:3000"}}},
	}), f)
	ctx := context.Background()
	if err := s.Forward(ctx, "off", 0, "localhost:3000", nil); !errors.Is(err, policy.ErrPermissionDenied) {
		t.Fatalf("capability off: %v", err)
	}
	if err := s.Forward(ctx, "limited", 0, "localhost:5432", nil); !errors.Is(err, policy.ErrPermissionDenied) {
		t.Fatalf("unlisted target: %v", err)
	}
	for _, target := range []string{"localhost", "localhost:0", ":3000"} {
		if err := s.Forward(ctx, "limited", 0, target, nil); err == nil {
			t.Fatalf("accepted target %q", target)
		}
	}
	if err := s.Forward(ctx, "limited", 70000, "localhost:3000", nil); err == nil {
		t.Fatal("accepted local port 70000")
	}
	if f.opened != 0 {
		t.Fatalf("refused forwards opened %d connections", f.opened)
	}
}
