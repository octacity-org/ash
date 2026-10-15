package ssh

import (
	"ash/internal/host"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"net"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/pkg/sftp"
	gossh "golang.org/x/crypto/ssh"
)

// pipeSSHResource builds a real sshResource whose client is connected to an
// in-process SSH server on a loopback listener. When reply is true the server
// answers global requests, so keepalive probes succeed; otherwise it swallows
// them, simulating a half-open connection whose probe would block forever.
func pipeSSHResource(t *testing.T, reply bool) (*sshResource, func()) {
	t.Helper()
	_, serverPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	serverKey, err := gossh.NewSignerFromKey(serverPrivate)
	if err != nil {
		t.Fatal(err)
	}
	serverConfig := &gossh.ServerConfig{NoClientAuth: true}
	serverConfig.AddHostKey(serverKey)
	// A loopback listener keeps the handshake fully asynchronous (real
	// sockets buffer), so no artificial synchronization is needed.
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	serverError := make(chan error, 1)
	go func() {
		conn, acceptErr := listener.Accept()
		if acceptErr != nil {
			serverError <- acceptErr
			return
		}
		_, _, serverRequests, err := gossh.NewServerConn(conn, serverConfig)
		if err == nil {
			// The server must consume its global-request channel and reply,
			// exactly like a real OpenSSH server answering keepalives. With
			// reply=false it swallows requests instead, which is what a
			// half-open connection looks like to the probe.
			for req := range serverRequests {
				if reply && req.WantReply {
					req.Reply(true, nil)
				}
			}
		}
		serverError <- err
	}()
	clientTCP, err := net.Dial("tcp", listener.Addr().String())
	if err != nil {
		listener.Close()
		t.Fatal(err)
	}
	clientSSH, chans, reqs, err := gossh.NewClientConn(clientTCP, listener.Addr().String(), &gossh.ClientConfig{
		User:            "u",
		Auth:            []gossh.AuthMethod{gossh.Password("")},
		HostKeyCallback: gossh.InsecureIgnoreHostKey(),
	})
	if err != nil {
		listener.Close()
		t.Fatal(err)
	}
	go func() {
		for req := range reqs {
			if reply && req.WantReply {
				req.Reply(true, nil)
			} else {
				// Swallow the request: no reply ever comes, which is what a
				// half-open connection looks like to the probe.
				_ = req
			}
		}
	}()

	res := &sshResource{client: gossh.NewClient(clientSSH, chans, reqs)}
	cleanup := func() {
		res.close()
		listener.Close()
	}
	t.Cleanup(cleanup)
	return res, cleanup
}

// The production health check succeeds against a live connection.
func TestSSHResourceHealthCheckSucceedsOnLiveConnection(t *testing.T) {
	res, _ := pipeSSHResource(t, true)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if !res.healthCheck(ctx) {
		t.Fatal("health check on a live connection must succeed")
	}
}

// healthCheck with a context that has no deadline would wait forever on a
// half-open connection, so the pool must always pass a deadline; document the
// contract by asserting a plain Background context still fails fast on a dead
// resource (nil client) rather than blocking.
func TestSSHResourceHealthCheckNilClientFailsFast(t *testing.T) {
	res := &sshResource{}
	if res.healthCheck(context.Background()) {
		t.Fatal("nil client must fail the health check")
	}
}

// A half-open connection (never any reply) is reported unusable once the
// probe's deadline fires, instead of blocking the caller forever.
func TestSSHResourceHealthCheckBoundsHalfOpenConnection(t *testing.T) {
	res, _ := pipeSSHResource(t, false)
	begin := time.Now()
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	if res.healthCheck(ctx) {
		t.Fatal("health check on a half-open connection must fail")
	}
	if elapsed := time.Since(begin); elapsed > 2*time.Second {
		t.Fatalf("probe waited %v; the deadline must bound it", elapsed)
	}
}

// Caller cancellation is honored even when the pool timeout has not fired.
func TestSSHResourceHealthCheckHonorsCancellation(t *testing.T) {
	res, _ := pipeSSHResource(t, false)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	begin := time.Now()
	go func() {
		time.Sleep(50 * time.Millisecond)
		cancel()
	}()
	if res.healthCheck(ctx) {
		t.Fatal("cancelled health check must fail")
	}
	if elapsed := time.Since(begin); elapsed > 2*time.Second {
		t.Fatalf("probe waited %v; cancellation must abort it", elapsed)
	}
}

// close runs the lifecycle cleanup exactly once and is safe to call repeatedly
// from different eviction paths.
func TestSSHResourceCloseRunsLifecycleExactlyOnce(t *testing.T) {
	res, _ := pipeSSHResource(t, true)
	cleanups := 0
	stopped := false
	res.setLifecycle(resourceLifecycle{
		stop:    func() bool { stopped = true; return true },
		cleanup: func() { cleanups++ },
	})
	first := res.close()
	second := res.close()
	third := res.close()
	_, _, _ = first, second, third
	if cleanups != 1 {
		t.Fatalf("lifecycle cleanup must run exactly once, ran %d times", cleanups)
	}
	if !stopped {
		t.Fatal("lifecycle stop must run")
	}
	if res.lifecycle.cleanup != nil || res.lifecycle.stop != nil {
		t.Fatal("lifecycle must be detached after close")
	}
}

// Dialing a real host is out of scope here; what must hold is that any
// sshResource the dial returns carries the lifecycle. dialSSH attaches it
// before the resource enters the pool, so simulate the wiring by asserting
// the production close path releases a live agent connection too.
func TestSSHResourceCloseClosesUnderlyingConnection(t *testing.T) {
	res, _ := pipeSSHResource(t, true)
	if !res.healthCheck(context.Background()) {
		t.Fatal("precondition: connection is live")
	}
	if err := res.close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	// A closed connection must fail the health check quickly (the probe
	// goroutine gets a send error or the deadline bounds it).
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()
	if res.healthCheck(ctx) {
		t.Fatal("health check after close must fail")
	}
}

// loopbackConn is a net.Conn whose addresses are placeholders; the tests only
// need working pipes over the loopback listener.
type loopbackConn struct {
	net.Conn
	addr net.Addr
}

func (l loopbackConn) LocalAddr() net.Addr  { return l.addr }
func (l loopbackConn) RemoteAddr() net.Addr { return l.addr }

// wiring: a production sshResource pooled by connect is closed exactly once
// across shutdown and a late release after shutdown.
func TestPooledResourceCloseOnceAcrossShutdownAndRelease(t *testing.T) {
	tr, err := New(filepath.Join(t.TempDir(), "known_hosts"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(tr.Close)

	cleanups := 0
	res, _ := pipeSSHResource(t, true)
	res.setLifecycle(resourceLifecycle{
		stop:    func() bool { return true },
		cleanup: func() { cleanups++ },
	})
	h := host.Host{Name: "wiring", Address: "127.0.0.1", Port: 0, User: "u"}
	key := keyFor(h, tr.knownHostsPath)

	// The exact put/get/release cycle the transport performs, with the real
	// health check of the live connection passing.
	tr.pool.reserve(context.Background())
	tr.pool.put(key, res)
	got, ok := tr.pool.get(context.Background(), key)
	if !ok || got != resource(res) {
		t.Fatal("expected the pooled resource to pass its health check")
	}
	// Shutdown while the resource is checked out closes nothing yet.
	tr.pool.Close()
	// The release after shutdown must close the resource exactly once: the
	// connection must be dead and the lifecycle detached, with exactly one
	// cleanup having run.
	tr.pool.put(key, got)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if res.healthCheck(ctx) {
		t.Fatal("release after shutdown must have closed the connection")
	}
	if cleanups != 1 {
		t.Fatalf("cleanup must run exactly once, ran %d times", cleanups)
	}
	if res.lifecycle.cleanup != nil || res.lifecycle.stop != nil {
		t.Fatal("lifecycle must be detached after close")
	}
}

// sftpSSHResource connects to an in-process SSH server that serves the SFTP
// subsystem from dir and counts how many SFTP sessions were opened.
func sftpSSHResource(t *testing.T, dir string) (*sshResource, *atomic.Int32) {
	t.Helper()
	_, serverPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	serverKey, err := gossh.NewSignerFromKey(serverPrivate)
	if err != nil {
		t.Fatal(err)
	}
	serverConfig := &gossh.ServerConfig{NoClientAuth: true}
	serverConfig.AddHostKey(serverKey)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { listener.Close() })
	sessions := new(atomic.Int32)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		_, chans, reqs, err := gossh.NewServerConn(conn, serverConfig)
		if err != nil {
			return
		}
		go gossh.DiscardRequests(reqs)
		for newChannel := range chans {
			channel, requests, err := newChannel.Accept()
			if err != nil {
				continue
			}
			go func() {
				for req := range requests {
					ok := req.Type == "subsystem" && len(req.Payload) > 4 && string(req.Payload[4:]) == "sftp"
					req.Reply(ok, nil)
					if ok {
						sessions.Add(1)
						server, err := sftp.NewServer(channel, sftp.WithServerWorkingDirectory(dir))
						if err == nil {
							go func() { server.Serve(); channel.Close() }()
						}
					}
				}
			}()
		}
	}()
	client, err := gossh.Dial("tcp", listener.Addr().String(), &gossh.ClientConfig{User: "u", Auth: []gossh.AuthMethod{gossh.Password("")}, HostKeyCallback: gossh.InsecureIgnoreHostKey()})
	if err != nil {
		t.Fatal(err)
	}
	res := &sshResource{client: client}
	t.Cleanup(func() { res.close() })
	return res, sessions
}

// A pooled connection keeps one SFTP session across file operations, so a
// root-checked read no longer opens a subsystem for canonicalization and
// another for the read. A session that ended is replaced transparently.
func TestPooledConnectionReusesSFTPSession(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "file.txt"), []byte("data"), 0o644); err != nil {
		t.Fatal(err)
	}
	res, sessions := sftpSSHResource(t, dir)
	tr, _ := newWiringHarness(t)
	tr.setDial(func(context.Context, host.Host) (*sshResource, error) { return res, nil })
	ctx := context.Background()
	h := hostForTest("sftp-reuse")
	if _, err := tr.Canonicalize(ctx, h, "file.txt"); err != nil {
		t.Fatal(err)
	}
	if data, err := tr.Read(ctx, h, "file.txt"); err != nil || string(data) != "data" {
		t.Fatalf("%q %v", data, err)
	}
	if _, err := tr.Stat(ctx, h, "file.txt"); err != nil {
		t.Fatal(err)
	}
	if n := sessions.Load(); n != 1 {
		t.Fatalf("opened %d SFTP sessions, want 1", n)
	}
	res.sftp.Close()
	if _, err := tr.Stat(ctx, h, "file.txt"); err != nil {
		t.Fatalf("after session end: %v", err)
	}
	if n := sessions.Load(); n != 2 {
		t.Fatalf("opened %d SFTP sessions after session end, want 2", n)
	}
}
