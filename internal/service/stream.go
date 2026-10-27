package service

import (
	"context"
	"errors"
	"fmt"
	"io"
	"sync"
	"time"

	"ash/internal/host"
	"ash/internal/policy"
	"ash/internal/transport"
)

var (
	errIdle        = errors.New("stream idle")
	errStreamLimit = errors.New("stream byte limit exceeded")
)

// ExecStream runs a command with local streams connected to the remote
// process. The request timeout bounds inactivity, not total duration: every
// chunk moved in either direction restarts it. The host's max_stream_bytes
// caps the bytes moved in both directions combined; the buffered stdin and
// output limits do not apply.
func (s *Service) ExecStream(ctx context.Context, req transport.ExecRequest, stdio transport.Stdio) (transport.ExecResult, error) {
	started := time.Now()
	h, err := s.authorize(req.Host, "exec")
	if err != nil {
		return transport.ExecResult{}, err
	}
	meter := &streamMeter{limit: h.Policy.MaxStreamBytes}
	result, err := s.execStream(ctx, h, req, meter, stdio)
	in, out := meter.totals()
	s.finish("exec", req.Host, started, err, usage{in: int(in), out: int(out)})
	return result, err
}

func (s *Service) execStream(ctx context.Context, h host.Host, req transport.ExecRequest, meter *streamMeter, stdio transport.Stdio) (transport.ExecResult, error) {
	name := req.Host
	if err := checkCommand(h, req); err != nil {
		return transport.ExecResult{}, err
	}
	timeout, err := execTimeout(h, req.Timeout)
	if err != nil {
		return transport.ExecResult{}, err
	}
	req.Timeout = timeout
	req.Stdin, req.StdinSet, req.MaxOutput = nil, false, 0
	ctx, cancel := context.WithCancelCause(ctx)
	defer cancel(nil)
	idle := time.AfterFunc(timeout, func() { cancel(errIdle) })
	defer idle.Stop()
	meter.touch = func() { idle.Reset(timeout) }
	meter.stop = cancel
	if err := ctx.Err(); err != nil {
		return transport.ExecResult{}, operationError(ctx, name, "exec", err)
	}
	if err := s.checkCwd(ctx, h, req); err != nil {
		return transport.ExecResult{}, err
	}
	stdio = transport.Stdio{Stdin: meter.reader(stdio.Stdin), Stdout: meter.writer(stdio.Stdout), Stderr: meter.writer(stdio.Stderr)}
	result, err := s.transport.ExecStream(ctx, h, req, stdio)
	if err == nil {
		return result, nil
	}
	cause := context.Cause(ctx)
	switch {
	case errors.Is(cause, errIdle):
		return result, fmt.Errorf("host %q: exec: %w: no data moved for %s", name, transport.ErrTimeout, timeout)
	case errors.Is(cause, errStreamLimit):
		return result, fmt.Errorf("host %q: exec: %w: stream exceeds %d bytes", name, policy.ErrPermissionDenied, meter.limit)
	case cause != nil && !errors.Is(cause, context.Canceled) && !errors.Is(cause, context.DeadlineExceeded):
		// A local stream failed, for example a closed stdout pipe.
		return result, fmt.Errorf("host %q: exec: %w", name, cause)
	}
	return result, operationError(ctx, name, "exec", err)
}

// streamMeter counts streamed bytes, restarts the idle timer on activity, and
// stops the operation when the byte limit is exceeded or a local stream fails.
type streamMeter struct {
	limit   int64
	touch   func()
	stop    context.CancelCauseFunc
	mu      sync.Mutex
	in, out int64
}

func (m *streamMeter) add(counter *int64, n int) error {
	m.mu.Lock()
	over := m.limit > 0 && m.in+m.out+int64(n) > m.limit
	if !over {
		*counter += int64(n)
	}
	m.mu.Unlock()
	if over {
		m.stop(errStreamLimit)
		return errStreamLimit
	}
	m.touch()
	return nil
}

func (m *streamMeter) totals() (in, out int64) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.in, m.out
}

func (m *streamMeter) reader(r io.Reader) io.Reader {
	if r == nil {
		return nil
	}
	return meteredReader{m: m, r: r}
}

func (m *streamMeter) writer(w io.Writer) io.Writer {
	if w == nil {
		w = io.Discard
	}
	return meteredWriter{m: m, w: w}
}

type meteredReader struct {
	m *streamMeter
	r io.Reader
}

// Read drops a chunk that would exceed the limit instead of forwarding it.
func (r meteredReader) Read(p []byte) (int, error) {
	n, err := r.r.Read(p)
	if n > 0 {
		if limitErr := r.m.add(&r.m.in, n); limitErr != nil {
			return 0, limitErr
		}
	}
	return n, err
}

type meteredWriter struct {
	m *streamMeter
	w io.Writer
}

func (w meteredWriter) Write(p []byte) (int, error) {
	if err := w.m.add(&w.m.out, len(p)); err != nil {
		return 0, err
	}
	n, err := w.w.Write(p)
	if err != nil {
		w.m.stop(err)
	}
	return n, err
}
