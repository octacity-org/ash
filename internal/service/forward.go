package service

import (
	"context"
	"fmt"
	"io"
	"net"
	"strconv"
	"sync"
	"time"

	"ash/internal/policy"
	"ash/internal/transport"
)

// Forward listens on 127.0.0.1:localPort and forwards each accepted connection
// to target, a host:port as seen from the remote host, through one SSH
// connection. It never listens on other addresses. ready, when set, receives
// the listening address. Forward returns nil once ctx ends, after closing the
// listener and every forwarded connection.
func (s *Service) Forward(ctx context.Context, name string, localPort int, target string, ready func(net.Addr)) error {
	started := time.Now()
	h, err := s.authorize(name, "forward")
	if err != nil {
		return err
	}
	if localPort < 0 || localPort > 65535 {
		return s.fail("forward", name, started, fmt.Errorf("local port must be between 0 and 65535"))
	}
	if err := policy.ValidateForwardTarget(target); err != nil {
		return s.fail("forward", name, started, err)
	}
	if err := h.Policy.CheckForwardTarget(target); err != nil {
		return s.fail("forward", name, started, fmt.Errorf("host %q: forward: %w", name, err))
	}
	connectCtx, cancel := context.WithTimeout(ctx, transport.DefaultFileTimeout)
	forwarder, err := s.transport.Forward(connectCtx, h)
	cancel()
	if err != nil {
		return s.fail("forward", name, started, operationError(connectCtx, name, "forward", err))
	}
	defer forwarder.Close()
	listener, err := net.Listen("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(localPort)))
	if err != nil {
		return s.fail("forward", name, started, err)
	}
	stop := context.AfterFunc(ctx, func() { listener.Close() })
	defer stop()
	if ready != nil {
		ready(listener.Addr())
	}
	var connections sync.WaitGroup
	defer connections.Wait()
	for {
		local, err := listener.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			listener.Close()
			return fmt.Errorf("host %q: forward: %w", name, err)
		}
		connections.Add(1)
		go func() {
			defer connections.Done()
			s.forwardConnection(ctx, name, forwarder, target, local)
		}()
	}
}

// forwardConnection copies one local connection to and from the target and
// audits it. Ending ctx closes both sides.
func (s *Service) forwardConnection(ctx context.Context, name string, forwarder transport.Forwarder, target string, local net.Conn) {
	started := time.Now()
	defer local.Close()
	remote, err := forwarder.Dial(ctx, target)
	if err != nil {
		s.finish("forward", name, started, err, usage{target: target})
		return
	}
	defer remote.Close()
	stop := context.AfterFunc(ctx, func() { local.Close(); remote.Close() })
	defer stop()
	var in int64
	sent := make(chan struct{})
	go func() {
		in, _ = io.Copy(remote, local)
		closeWrite(remote)
		close(sent)
	}()
	out, _ := io.Copy(local, remote)
	closeWrite(local)
	<-sent
	s.finish("forward", name, started, nil, usage{in: int(in), out: int(out), target: target})
}

// closeWrite half-closes a connection so the peer sees EOF while replies can
// still arrive.
func closeWrite(conn net.Conn) {
	if c, ok := conn.(interface{ CloseWrite() error }); ok {
		c.CloseWrite()
	}
}
