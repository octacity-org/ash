package ssh

import (
	"ash/internal/host"
	"ash/internal/transport"
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	gossh "golang.org/x/crypto/ssh"
)

// execSSHResource connects to an in-process SSH server whose exec handler
// echoes stdin to stdout until EOF and exits with status 3. The command
// "exit-now" exits immediately without reading stdin, and "hang" never exits.
func execSSHResource(t *testing.T) *sshResource {
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
					if req.Type != "exec" || len(req.Payload) < 4 {
						req.Reply(false, nil)
						continue
					}
					command := string(req.Payload[4:])
					req.Reply(true, nil)
					go func() {
						switch command {
						case "hang":
							return
						case "exit-now":
						default:
							io.Copy(channel, channel)
						}
						channel.SendRequest("exit-status", false, gossh.Marshal(struct{ Status uint32 }{3}))
						channel.Close()
					}()
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
	return res
}

func streamHarness(t *testing.T) (*Transport, host.Host) {
	t.Helper()
	res := execSSHResource(t)
	tr, _ := newWiringHarness(t)
	tr.setDial(func(context.Context, host.Host) (*sshResource, error) { return res, nil })
	return tr, hostForTest("stream")
}

func TestExecStreamMovesUnboundedBytesAndExitCode(t *testing.T) {
	tr, h := streamHarness(t)
	input := bytes.Repeat([]byte("0123456789abcdef"), (transport.MaxOutputSize+1)/16+1)
	var out bytes.Buffer
	r, err := tr.ExecStream(context.Background(), h, transport.ExecRequest{Command: "cat"}, transport.Stdio{Stdin: bytes.NewReader(input), Stdout: &out, Stderr: io.Discard})
	if err != nil || r.ExitCode != 3 {
		t.Fatalf("%+v %v", r, err)
	}
	if !bytes.Equal(out.Bytes(), input) {
		t.Fatalf("echoed %d of %d bytes", out.Len(), len(input))
	}
}

// The remote command may exit while local stdin is still open, as rsync's
// remote side does; the stream must end with it instead of waiting for EOF.
func TestExecStreamEndsWhenRemoteExitsWithStdinOpen(t *testing.T) {
	tr, h := streamHarness(t)
	stdin, writer := io.Pipe()
	t.Cleanup(func() { writer.Close() })
	done := make(chan error, 1)
	go func() {
		r, err := tr.ExecStream(context.Background(), h, transport.ExecRequest{Command: "exit-now"}, transport.Stdio{Stdin: stdin, Stdout: io.Discard, Stderr: io.Discard})
		if err == nil && r.ExitCode != 3 {
			err = io.ErrUnexpectedEOF
		}
		done <- err
	}()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("stream waited for local stdin after the remote command exited")
	}
}

func TestExecStreamCancellationClosesSession(t *testing.T) {
	tr, h := streamHarness(t)
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	started := time.Now()
	_, err := tr.ExecStream(ctx, h, transport.ExecRequest{Command: "hang"}, transport.Stdio{Stdout: io.Discard, Stderr: io.Discard})
	if err == nil {
		t.Fatal("hung command returned no error")
	}
	if elapsed := time.Since(started); elapsed > 5*time.Second {
		t.Fatalf("cancellation took %s", elapsed)
	}
}

func TestFileStreamsMoveFilesLargerThanReadLimit(t *testing.T) {
	f := newSFTPFixture(t)
	ctx := context.Background()
	data := bytes.Repeat([]byte("streamed-file\n"), (transport.MaxWriteSize/14)+1000)
	for _, atomic := range []bool{false, true} {
		target := "large.bin"
		if atomic {
			target = "large-atomic.bin"
		}
		if err := f.tr.WriteStream(ctx, f.h, target, bytes.NewBuffer(data), atomic); err != nil {
			t.Fatalf("atomic=%v: %v", atomic, err)
		}
		var out bytes.Buffer
		if err := f.tr.ReadStream(ctx, f.h, target, &out); err != nil || !bytes.Equal(out.Bytes(), data) {
			t.Fatalf("atomic=%v: read %d of %d bytes: %v", atomic, out.Len(), len(data), err)
		}
	}
}

// failingReader yields some bytes, then runs fail and returns its error.
type failingReader struct {
	remaining int
	fail      func() error
}

func (r *failingReader) Read(p []byte) (int, error) {
	if r.remaining == 0 {
		return 0, r.fail()
	}
	n := min(len(p), r.remaining)
	r.remaining -= n
	return n, nil
}

func TestAtomicWriteStreamFailureKeepsDestination(t *testing.T) {
	f := newSFTPFixture(t)
	target := "keep.txt"
	if err := os.WriteFile(filepath.Join(f.root, target), []byte("previous"), 0o600); err != nil {
		t.Fatal(err)
	}
	broken := errors.New("input failed")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	cases := []struct {
		name string
		fail func() error
	}{
		{"input error", func() error { return broken }},
		// A cancelled transfer still removes its temporary file, because the
		// session stays open for streamCloseGrace.
		{"cancelled", func() error { cancel(); return context.Canceled }},
	}
	for _, c := range cases {
		name := c.name
		err := f.tr.WriteStream(ctx, f.h, target, &failingReader{remaining: 1 << 20, fail: c.fail}, true)
		if err == nil {
			t.Fatalf("%s: write succeeded", name)
		}
		data, readErr := os.ReadFile(filepath.Join(f.root, target))
		if readErr != nil || string(data) != "previous" {
			t.Fatalf("%s: destination = %q %v", name, data, readErr)
		}
		entries, _ := os.ReadDir(f.root)
		for _, entry := range entries {
			if strings.HasPrefix(entry.Name(), ".ash-tmp-") {
				t.Fatalf("%s: temporary file %s left behind", name, entry.Name())
			}
		}
	}
}
