package ssh

import (
	"ash/internal/host"
	"ash/internal/transport"
	"context"
	"net"
	"sync"

	gossh "golang.org/x/crypto/ssh"
)

// forwarder holds one claimed SSH connection for a forwarding session, so
// every forwarded TCP connection shares it instead of claiming its own.
type forwarder struct {
	client  *gossh.Client
	release func()
	once    sync.Once
}

func (t *Transport) Forward(ctx context.Context, h host.Host) (transport.Forwarder, error) {
	client, release, err := t.connect(ctx, h)
	if err != nil {
		return nil, err
	}
	return &forwarder{client: client, release: release}, nil
}

// Dial opens a direct-tcpip channel to address from the remote host.
func (f *forwarder) Dial(ctx context.Context, address string) (net.Conn, error) {
	conn, err := f.client.DialContext(ctx, "tcp", address)
	if err != nil {
		return nil, operationError(ctx, err)
	}
	return conn, nil
}

func (f *forwarder) Close() error {
	f.once.Do(f.release)
	return nil
}
