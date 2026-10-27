package ssh

import (
	"ash/internal/host"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"io"
	"net"
	"strconv"
	"testing"

	gossh "golang.org/x/crypto/ssh"
)

// tcpipSSHResource connects to an in-process SSH server that serves
// direct-tcpip channels by dialing the requested target itself, like sshd
// with AllowTcpForwarding. It counts the SSH connections it accepts.
func tcpipSSHResource(t *testing.T) (*sshResource, *int) {
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
	accepted := new(int)
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			*accepted++
			_, chans, reqs, err := gossh.NewServerConn(conn, serverConfig)
			if err != nil {
				continue
			}
			go gossh.DiscardRequests(reqs)
			go func() {
				for newChannel := range chans {
					var payload struct {
						Host       string
						Port       uint32
						OriginHost string
						OriginPort uint32
					}
					if newChannel.ChannelType() != "direct-tcpip" || gossh.Unmarshal(newChannel.ExtraData(), &payload) != nil {
						newChannel.Reject(gossh.UnknownChannelType, "unsupported")
						continue
					}
					target, err := net.Dial("tcp", net.JoinHostPort(payload.Host, strconv.Itoa(int(payload.Port))))
					if err != nil {
						newChannel.Reject(gossh.ConnectionFailed, err.Error())
						continue
					}
					channel, requests, err := newChannel.Accept()
					if err != nil {
						target.Close()
						continue
					}
					go gossh.DiscardRequests(requests)
					go func() {
						io.Copy(target, channel)
						target.(*net.TCPConn).CloseWrite()
					}()
					go func() {
						io.Copy(channel, target)
						channel.CloseWrite()
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
	return res, accepted
}

func TestForwarderDialsTargetsOverOneConnection(t *testing.T) {
	echo, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer echo.Close()
	go func() {
		for {
			conn, err := echo.Accept()
			if err != nil {
				return
			}
			go func() { io.Copy(conn, conn); conn.Close() }()
		}
	}()
	res, accepted := tcpipSSHResource(t)
	tr, _ := newWiringHarness(t)
	dials := 0
	tr.setDial(func(context.Context, host.Host) (*sshResource, error) { dials++; return res, nil })
	ctx := context.Background()
	forwarder, err := tr.Forward(ctx, hostForTest("forward"))
	if err != nil {
		t.Fatal(err)
	}
	defer forwarder.Close()
	for i := 0; i < 3; i++ {
		conn, err := forwarder.Dial(ctx, echo.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		conn.Write([]byte("hello"))
		conn.(interface{ CloseWrite() error }).CloseWrite()
		reply, err := io.ReadAll(conn)
		conn.Close()
		if err != nil || string(reply) != "hello" {
			t.Fatalf("connection %d: %q %v", i, reply, err)
		}
	}
	if dials != 1 || *accepted != 1 {
		t.Fatalf("dialed %d times, server accepted %d connections; want one shared connection", dials, *accepted)
	}
	if _, err := forwarder.Dial(ctx, "127.0.0.1:1"); err == nil {
		t.Fatal("dial to a closed port succeeded")
	}
}
