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

// fileStreamTimeout bounds inactivity of streamed file transfers.
var fileStreamTimeout = transport.DefaultFileTimeout

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
	ctx, done := meter.start(ctx, timeout)
	defer done()
	if err := ctx.Err(); err != nil {
		return transport.ExecResult{}, operationError(ctx, name, "exec", err)
	}
	if err := s.checkCwd(ctx, h, req); err != nil {
		return transport.ExecResult{}, err
	}
	stdio = transport.Stdio{Stdin: meter.reader(stdio.Stdin), Stdout: meter.writer(stdio.Stdout), Stderr: meter.writer(stdio.Stderr)}
	result, err := s.transport.ExecStream(ctx, h, req, stdio)
	return result, meter.err(ctx, name, "exec", timeout, err)
}

// ReadStream copies a whole remote file to w without the 4 MiB read limit.
// Read roots apply as for Read; the 30-second file timeout bounds inactivity
// rather than the whole transfer, and max_stream_bytes caps it.
func (s *Service) ReadStream(ctx context.Context, name, path string, w io.Writer) error {
	started := time.Now()
	h, err := s.authorize(name, "read")
	if err != nil {
		return err
	}
	if path == "" {
		return s.fail("read", name, started, fmt.Errorf("path must not be empty"))
	}
	meter := &streamMeter{limit: h.Policy.MaxStreamBytes}
	ctx, done := meter.start(ctx, fileStreamTimeout)
	defer done()
	if err := s.enforceRoots(ctx, h, name, "read", path, false); err != nil {
		return s.fail("read", name, started, err)
	}
	err = s.transport.ReadStream(ctx, h, path, meter.writer(w))
	err = meter.err(ctx, name, "read", fileStreamTimeout, err)
	_, out := meter.totals()
	s.finish("read", name, started, err, usage{out: int(out)})
	return err
}

// WriteStream creates or truncates a remote file from r without the 4 MiB
// write limit, under the same rules as ReadStream. With atomic set, the file
// is replaced through a temporary file like AtomicWrite.
func (s *Service) WriteStream(ctx context.Context, name, path string, r io.Reader, atomic bool) error {
	started := time.Now()
	operation := "write"
	if atomic {
		operation = "write atomic"
	}
	h, err := s.authorize(name, "write")
	if err != nil {
		return err
	}
	if path == "" {
		return s.fail(operation, name, started, fmt.Errorf("path must not be empty"))
	}
	meter := &streamMeter{limit: h.Policy.MaxStreamBytes}
	ctx, done := meter.start(ctx, fileStreamTimeout)
	defer done()
	if err := s.enforceRoots(ctx, h, name, operation, path, true); err != nil {
		return s.fail(operation, name, started, err)
	}
	err = s.transport.WriteStream(ctx, h, path, meter.reader(contextReader{ctx: ctx, r: r}), atomic)
	err = meter.err(ctx, name, operation, fileStreamTimeout, err)
	in, _ := meter.totals()
	s.finish(operation, name, started, err, usage{in: int(in)})
	return err
}

// contextReader returns once its context ends even while the underlying
// Read is blocked, for example on a terminal or an idle pipe. The blocked
// Read finishes in the background and its data is discarded.
type contextReader struct {
	ctx context.Context
	r   io.Reader
}

func (c contextReader) Read(p []byte) (int, error) {
	if err := c.ctx.Err(); err != nil {
		return 0, context.Cause(c.ctx)
	}
	type result struct {
		n   int
		err error
	}
	buffer := make([]byte, len(p))
	read := make(chan result, 1)
	go func() {
		n, err := c.r.Read(buffer)
		read <- result{n, err}
	}()
	select {
	case r := <-read:
		return copy(p, buffer[:r.n]), r.err
	case <-c.ctx.Done():
		return 0, context.Cause(c.ctx)
	}
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

// start returns a context that ends when no data moves for timeout or when
// the meter stops the operation, and the function that releases it.
func (m *streamMeter) start(ctx context.Context, timeout time.Duration) (context.Context, func()) {
	ctx, cancel := context.WithCancelCause(ctx)
	idle := time.AfterFunc(timeout, func() { cancel(errIdle) })
	m.touch = func() { idle.Reset(timeout) }
	m.stop = cancel
	return ctx, func() { idle.Stop(); cancel(nil) }
}

// err reports why a streamed operation failed, preferring the reason the
// meter stopped it over the transport error that the stop caused.
func (m *streamMeter) err(ctx context.Context, name, operation string, timeout time.Duration, err error) error {
	if err == nil {
		return nil
	}
	cause := context.Cause(ctx)
	switch {
	case errors.Is(cause, errIdle):
		return fmt.Errorf("host %q: %s: %w: no data moved for %s", name, operation, transport.ErrTimeout, timeout)
	case errors.Is(cause, errStreamLimit):
		return fmt.Errorf("host %q: %s: %w: stream exceeds %d bytes", name, operation, policy.ErrPermissionDenied, m.limit)
	case cause != nil && !errors.Is(cause, context.Canceled) && !errors.Is(cause, context.DeadlineExceeded):
		// A local stream failed, for example a closed stdout pipe.
		return fmt.Errorf("host %q: %s: %w", name, operation, cause)
	}
	return operationError(ctx, name, operation, err)
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
