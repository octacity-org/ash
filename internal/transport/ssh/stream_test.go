package ssh

import (
	"ash/internal/host"
	"ash/internal/transport"
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"io"
	"net"
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
