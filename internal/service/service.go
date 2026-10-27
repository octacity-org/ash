// Package service owns host resolution, authorization and operation deadlines.
package service

import (
	"context"
	"errors"
	"fmt"
	"time"
	"unicode/utf8"

	"ash/internal/audit"
	"ash/internal/host"
	"ash/internal/transport"
)

type Service struct {
	hosts     *host.Registry
	transport transport.Transport
	audit     *audit.Recorder
}

func New(hosts *host.Registry, t transport.Transport) *Service {
	return &Service{hosts: hosts, transport: t}
}

// WithAudit attaches one audit recorder to the service.
func (s *Service) WithAudit(recorder *audit.Recorder) *Service {
	s.audit = recorder
	return s
}

// HostInfo describes a host and the policy limits an agent will meet, so it
// can plan within them instead of discovering them through refusals.
type HostInfo struct {
	Name         string   `json:"name"`
	Address      string   `json:"address"`
	User         string   `json:"user"`
	Capabilities []string `json:"capabilities"`
	ShellBackend string   `json:"shell_backend,omitempty"`

	ReadRoots         []string `json:"read_roots,omitempty"`
	WriteRoots        []string `json:"write_roots,omitempty"`
	CwdRoots          []string `json:"cwd_roots,omitempty"`
	AllowedCommands   []string `json:"allowed_commands,omitempty"`
	AllowShell        bool     `json:"allow_shell,omitempty"`
	MaxTimeoutSeconds int      `json:"max_timeout_seconds,omitempty"`
	MaxInputBytes     int64    `json:"max_input_bytes,omitempty"`
	MaxOutputBytes    int64    `json:"max_output_bytes,omitempty"`
	MaxStreamBytes    int64    `json:"max_stream_bytes,omitempty"`
	ForwardTargets    []string `json:"forward_targets,omitempty"`
}

func (s *Service) Hosts() []HostInfo {
	out := make([]HostInfo, 0)
	for _, h := range s.hosts.List() {
		caps := make([]string, 0, 3)
		if h.Policy.Exec {
			caps = append(caps, "exec")
		}
		if h.Policy.Read {
			caps = append(caps, "read")
		}
		if h.Policy.Write {
			caps = append(caps, "write")
		}
		if h.Policy.Forward {
			caps = append(caps, "forward")
		}
		p := h.Policy
		out = append(out, HostInfo{
			Name: h.Name, Address: h.Address, User: h.User, Capabilities: caps, ShellBackend: h.ShellBackend,
			ReadRoots: p.ReadRoots, WriteRoots: p.WriteRoots, CwdRoots: p.CwdRoots,
			AllowedCommands: p.AllowedCommands, AllowShell: p.AllowShell,
			MaxTimeoutSeconds: p.MaxTimeoutSeconds, MaxInputBytes: p.MaxInputBytes, MaxOutputBytes: p.MaxOutputBytes,
			MaxStreamBytes: p.MaxStreamBytes, ForwardTargets: p.ForwardTargets,
		})
	}
	return out
}

func (s *Service) resolve(name, operation string) (host.Host, error) {
	h, err := s.hosts.Get(name)
	if err != nil {
		return h, err
	}
	if err = h.Policy.Check(operation); err != nil {
		return h, fmt.Errorf("host %q: %s: %w", name, operation, err)
	}
	return h, nil
}

// authorize resolves a host and records refusals.
func (s *Service) authorize(name, operation string) (host.Host, error) {
	h, err := s.resolve(name, operation)
	if err != nil {
		s.audit.Record(audit.Record{Operation: operation, Host: name, Decision: audit.Denied, Result: audit.ResultError})
	}
	return h, err
}

// usage is the payload an operation moved: in is sent to the remote host
// (stdin, written content), out is returned from it (output, read content).
type usage struct {
	in, out   int
	truncated bool
	target    string
}

func treeBytes(entries []transport.TreeEntry) int {
	n := 0
	for _, entry := range entries {
		n += len(entry.Data)
	}
	return n
}

func (s *Service) finish(operation, name string, started time.Time, err error, u usage) {
	if s.audit == nil {
		return
	}
	record := audit.Record{Operation: operation, Host: name, Decision: audit.Allowed, Result: audit.ResultOK, DurationMS: time.Since(started).Milliseconds(),
		BytesIn: int64(u.in), BytesOut: int64(u.out), Truncated: u.truncated, Target: u.target}
	if err != nil {
		record.Result = audit.ResultError
		if errors.Is(err, transport.ErrTimeout) {
			record.Result = audit.ResultTimeout
		}
	}
	s.audit.Record(record)
}

func (s *Service) fail(operation, name string, started time.Time, err error) error {
	s.finish(operation, name, started, err, usage{})
	return err
}

// enforceRoots canonicalizes a remote path and checks it against policy roots.
// It performs no extra round trip when the host is unconstrained.
func (s *Service) enforceRoots(ctx context.Context, h host.Host, name, operation, p string, write bool) error {
	if !h.Policy.HasRoots(write) {
		return nil
	}
	canonical, err := s.transport.Canonicalize(ctx, h, p)
	if err != nil {
		return operationError(ctx, name, operation, err)
	}
	if err := h.Policy.CheckRoots(canonical, write); err != nil {
		return fmt.Errorf("host %q: %s: %w", name, operation, err)
	}
	return nil
}

func operationError(ctx context.Context, name, op string, err error) error {
	if err == nil {
		return nil
	}
	if ctx.Err() != nil {
		err = ctx.Err()
		if err == context.DeadlineExceeded {
			err = fmt.Errorf("%w: %w", transport.ErrTimeout, err)
		}
	}
	return fmt.Errorf("host %q: %s: %w", name, op, err)
}

func (s *Service) Exec(ctx context.Context, req transport.ExecRequest) (transport.ExecResult, error) {
	started := time.Now()
	h, err := s.authorize(req.Host, "exec")
	if err != nil {
		return transport.ExecResult{}, err
	}
	result, err := s.exec(ctx, h, req)
	s.finish("exec", req.Host, started, err, usage{in: len(req.Stdin), out: len(result.Stdout) + len(result.Stderr), truncated: result.StdoutTruncated || result.StderrTruncated})
	return result, err
}

// checkCommand enforces the command shape and the executable policy shared by
// buffered and streamed exec.
func checkCommand(h host.Host, req transport.ExecRequest) error {
	argv := len(req.Argv) > 0
	switch {
	case argv && req.Command != "":
		return fmt.Errorf("command and argv are mutually exclusive")
	case !argv && req.Command == "":
		return fmt.Errorf("command must not be empty")
	}
	if argv {
		if req.Argv[0] == "" {
			return fmt.Errorf("argv program must not be empty")
		}
		if err := h.Policy.CheckExecutable(req.Argv[0]); err != nil {
			return fmt.Errorf("host %q: exec: %w", req.Host, err)
		}
	} else if err := h.Policy.CheckShell(); err != nil {
		return fmt.Errorf("host %q: exec: %w", req.Host, err)
	}
	return nil
}

// execTimeout applies the default and the policy cap to a requested timeout.
func execTimeout(h host.Host, timeout time.Duration) (time.Duration, error) {
	if timeout < 0 {
		return 0, fmt.Errorf("timeout must be positive")
	}
	if timeout == 0 {
		timeout = transport.DefaultExecTimeout
	}
	if limit := h.Policy.MaxTimeout(); limit > 0 && timeout > limit {
		timeout = limit
	}
	return timeout, nil
}

// checkCwd enforces cwd roots against the canonical working directory.
func (s *Service) checkCwd(ctx context.Context, h host.Host, req transport.ExecRequest) error {
	if req.Cwd == "" || len(h.Policy.CwdRoots) == 0 {
		return nil
	}
	canonical, err := s.transport.Canonicalize(ctx, h, req.Cwd)
	if err != nil {
		return operationError(ctx, req.Host, "exec", err)
	}
	if err := h.Policy.CheckCwd(canonical); err != nil {
		return fmt.Errorf("host %q: exec: %w", req.Host, err)
	}
	return nil
}

func (s *Service) exec(ctx context.Context, h host.Host, req transport.ExecRequest) (transport.ExecResult, error) {
	name := req.Host
	if err := checkCommand(h, req); err != nil {
		return transport.ExecResult{}, err
	}
	if len(req.Stdin) > transport.MaxExecInputSize {
		return transport.ExecResult{}, fmt.Errorf("exec input exceeds %d byte limit", transport.MaxExecInputSize)
	}
	if err := h.Policy.CheckInput(len(req.Stdin)); err != nil {
		return transport.ExecResult{}, fmt.Errorf("host %q: exec: %w", name, err)
	}
	timeout, err := execTimeout(h, req.Timeout)
	if err != nil {
		return transport.ExecResult{}, err
	}
	req.Timeout = timeout
	if h.Policy.MaxOutputBytes > 0 {
		req.MaxOutput = int(h.Policy.MaxOutputBytes)
	}
	ctx, cancel := context.WithTimeout(ctx, req.Timeout)
	defer cancel()
	if err := ctx.Err(); err != nil {
		return transport.ExecResult{}, operationError(ctx, name, "exec", err)
	}
	if err := s.checkCwd(ctx, h, req); err != nil {
		return transport.ExecResult{}, err
	}
	result, err := s.transport.Exec(ctx, h, req)
	return result, operationError(ctx, name, "exec", err)
}

func (s *Service) Read(ctx context.Context, name, path string) ([]byte, error) {
	started := time.Now()
	h, err := s.authorize(name, "read")
	if err != nil {
		return nil, err
	}
	if path == "" {
		return nil, s.fail("read", name, started, fmt.Errorf("path must not be empty"))
	}
	ctx, cancel := context.WithTimeout(ctx, transport.DefaultFileTimeout)
	defer cancel()
	if err := ctx.Err(); err != nil {
		return nil, s.fail("read", name, started, operationError(ctx, name, "read", err))
	}
	if err := s.enforceRoots(ctx, h, name, "read", path, false); err != nil {
		return nil, s.fail("read", name, started, err)
	}
	data, err := s.transport.Read(ctx, h, path)
	err = operationError(ctx, name, "read", err)
	s.finish("read", name, started, err, usage{out: len(data)})
	return data, err
}

// ReadRange reads a bounded slice of a file. A zero limit means MaxReadSize;
// a negative offset counts back from the end of the file.
func (s *Service) ReadRange(ctx context.Context, name, path string, offset, limit int64) (transport.FileRange, error) {
	started := time.Now()
	h, err := s.authorize(name, "read")
	if err != nil {
		return transport.FileRange{}, err
	}
	if path == "" {
		return transport.FileRange{}, s.fail("read", name, started, fmt.Errorf("path must not be empty"))
	}
	if limit < 0 || limit > transport.MaxReadSize {
		return transport.FileRange{}, s.fail("read", name, started, fmt.Errorf("limit must be between 0 and %d", transport.MaxReadSize))
	}
	if limit == 0 {
		limit = transport.MaxReadSize
	}
	ctx, cancel := context.WithTimeout(ctx, transport.DefaultFileTimeout)
	defer cancel()
	if err := ctx.Err(); err != nil {
		return transport.FileRange{}, s.fail("read", name, started, operationError(ctx, name, "read", err))
	}
	if err := s.enforceRoots(ctx, h, name, "read", path, false); err != nil {
		return transport.FileRange{}, s.fail("read", name, started, err)
	}
	r, err := s.transport.ReadRange(ctx, h, path, offset, limit)
	err = operationError(ctx, name, "read", err)
	s.finish("read", name, started, err, usage{out: len(r.Data)})
	return r, err
}

func (s *Service) Write(ctx context.Context, name, path string, data []byte) error {
	started := time.Now()
	h, err := s.authorize(name, "write")
	if err != nil {
		return err
	}
	if path == "" {
		return s.fail("write", name, started, fmt.Errorf("path must not be empty"))
	}
	if len(data) > transport.MaxWriteSize {
		return s.fail("write", name, started, fmt.Errorf("write exceeds %d byte limit", transport.MaxWriteSize))
	}
	ctx, cancel := context.WithTimeout(ctx, transport.DefaultFileTimeout)
	defer cancel()
	if err := ctx.Err(); err != nil {
		return s.fail("write", name, started, operationError(ctx, name, "write", err))
	}
	if err := s.enforceRoots(ctx, h, name, "write", path, true); err != nil {
		return s.fail("write", name, started, err)
	}
	err = operationError(ctx, name, "write", s.transport.Write(ctx, h, path, data))
	s.finish("write", name, started, err, usage{in: len(data)})
	return err
}

func (s *Service) Stat(ctx context.Context, name, path string) (transport.FileInfo, error) {
	started := time.Now()
	h, err := s.authorize(name, "stat")
	if err != nil {
		return transport.FileInfo{}, err
	}
	if path == "" {
		return transport.FileInfo{}, s.fail("stat", name, started, fmt.Errorf("path must not be empty"))
	}
	ctx, cancel := context.WithTimeout(ctx, transport.DefaultFileTimeout)
	defer cancel()
	if err := ctx.Err(); err != nil {
		return transport.FileInfo{}, s.fail("stat", name, started, operationError(ctx, name, "stat", err))
	}
	if err := s.enforceRoots(ctx, h, name, "stat", path, false); err != nil {
		return transport.FileInfo{}, s.fail("stat", name, started, err)
	}
	result, err := s.transport.Stat(ctx, h, path)
	err = operationError(ctx, name, "stat", err)
	s.finish("stat", name, started, err, usage{})
	return result, err
}

func (s *Service) List(ctx context.Context, name, p string) ([]transport.DirEntry, error) {
	started := time.Now()
	h, err := s.authorize(name, "read")
	if err != nil {
		return nil, err
	}
	if p == "" {
		return nil, s.fail("list", name, started, fmt.Errorf("path must not be empty"))
	}
	ctx, cancel := context.WithTimeout(ctx, transport.DefaultFileTimeout)
	defer cancel()
	if err := ctx.Err(); err != nil {
		return nil, s.fail("list", name, started, operationError(ctx, name, "list", err))
	}
	if err := s.enforceRoots(ctx, h, name, "list", p, false); err != nil {
		return nil, s.fail("list", name, started, err)
	}
	entries, err := s.transport.List(ctx, h, p)
	err = operationError(ctx, name, "list", err)
	s.finish("list", name, started, err, usage{})
	return entries, err
}

func (s *Service) Mkdir(ctx context.Context, name, p string) error {
	started := time.Now()
	h, err := s.authorize(name, "write")
	if err != nil {
		return err
	}
	if p == "" {
		return s.fail("mkdir", name, started, fmt.Errorf("path must not be empty"))
	}
	ctx, cancel := context.WithTimeout(ctx, transport.DefaultFileTimeout)
	defer cancel()
	if err := ctx.Err(); err != nil {
		return s.fail("mkdir", name, started, operationError(ctx, name, "mkdir", err))
	}
	if err := s.enforceRoots(ctx, h, name, "mkdir", p, true); err != nil {
		return s.fail("mkdir", name, started, err)
	}
	err = operationError(ctx, name, "mkdir", s.transport.Mkdir(ctx, h, p))
	s.finish("mkdir", name, started, err, usage{})
	return err
}

func (s *Service) Rename(ctx context.Context, name, from, to string) error {
	started := time.Now()
	h, err := s.authorize(name, "write")
	if err != nil {
		return err
	}
	if from == "" || to == "" {
		return s.fail("rename", name, started, fmt.Errorf("source and destination must not be empty"))
	}
	ctx, cancel := context.WithTimeout(ctx, transport.DefaultFileTimeout)
	defer cancel()
	if err := ctx.Err(); err != nil {
		return s.fail("rename", name, started, operationError(ctx, name, "rename", err))
	}
	if err := s.enforceRoots(ctx, h, name, "rename", from, true); err != nil {
		return s.fail("rename", name, started, err)
	}
	if err := s.enforceRoots(ctx, h, name, "rename", to, true); err != nil {
		return s.fail("rename", name, started, err)
	}
	err = operationError(ctx, name, "rename", s.transport.Rename(ctx, h, from, to))
	s.finish("rename", name, started, err, usage{})
	return err
}

func (s *Service) Remove(ctx context.Context, name, p string) error {
	started := time.Now()
	h, err := s.authorize(name, "write")
	if err != nil {
		return err
	}
	if p == "" {
		return s.fail("remove", name, started, fmt.Errorf("path must not be empty"))
	}
	ctx, cancel := context.WithTimeout(ctx, transport.DefaultFileTimeout)
	defer cancel()
	if err := ctx.Err(); err != nil {
		return s.fail("remove", name, started, operationError(ctx, name, "remove", err))
	}
	if err := s.enforceRoots(ctx, h, name, "remove", p, true); err != nil {
		return s.fail("remove", name, started, err)
	}
	err = operationError(ctx, name, "remove", s.transport.Remove(ctx, h, p))
	s.finish("remove", name, started, err, usage{})
	return err
}

// AtomicWrite replaces a remote file completely or leaves the prior file intact.
func (s *Service) AtomicWrite(ctx context.Context, name, p string, data []byte) error {
	started := time.Now()
	h, err := s.authorize(name, "write")
	if err != nil {
		return err
	}
	if p == "" {
		return s.fail("write atomic", name, started, fmt.Errorf("path must not be empty"))
	}
	if len(data) > transport.MaxWriteSize {
		return s.fail("write atomic", name, started, fmt.Errorf("write exceeds %d byte limit", transport.MaxWriteSize))
	}
	ctx, cancel := context.WithTimeout(ctx, transport.DefaultFileTimeout)
	defer cancel()
	if err := ctx.Err(); err != nil {
		return s.fail("write atomic", name, started, operationError(ctx, name, "write atomic", err))
	}
	if err := s.enforceRoots(ctx, h, name, "write atomic", p, true); err != nil {
		return s.fail("write atomic", name, started, err)
	}
	err = operationError(ctx, name, "write atomic", s.transport.AtomicWrite(ctx, h, p, data))
	s.finish("write atomic", name, started, err, usage{in: len(data)})
	return err
}

// ReadTree returns a bounded, symlink-free tree rooted at a remote directory.
func (s *Service) ReadTree(ctx context.Context, name, p string) ([]transport.TreeEntry, error) {
	started := time.Now()
	h, err := s.authorize(name, "read")
	if err != nil {
		return nil, err
	}
	if p == "" {
		return nil, s.fail("download", name, started, fmt.Errorf("path must not be empty"))
	}
	ctx, cancel := context.WithTimeout(ctx, transport.DefaultFileTimeout)
	defer cancel()
	if err := ctx.Err(); err != nil {
		return nil, s.fail("download", name, started, operationError(ctx, name, "download", err))
	}
	if err := s.enforceRoots(ctx, h, name, "download", p, false); err != nil {
		return nil, s.fail("download", name, started, err)
	}
	entries, err := s.transport.ReadTree(ctx, h, p)
	err = operationError(ctx, name, "download", err)
	s.finish("download", name, started, err, usage{out: treeBytes(entries)})
	return entries, err
}

// WriteTree validates and uploads a bounded tree rooted at a remote directory.
func (s *Service) WriteTree(ctx context.Context, name, p string, entries []transport.TreeEntry) error {
	started := time.Now()
	h, err := s.authorize(name, "write")
	if err != nil {
		return err
	}
	if err := transport.ValidateTree(p, entries); err != nil {
		return s.fail("upload", name, started, err)
	}
	ctx, cancel := context.WithTimeout(ctx, transport.DefaultFileTimeout)
	defer cancel()
	if err := ctx.Err(); err != nil {
		return s.fail("upload", name, started, operationError(ctx, name, "upload", err))
	}
	if err := s.enforceRoots(ctx, h, name, "upload", p, true); err != nil {
		return s.fail("upload", name, started, err)
	}
	err = operationError(ctx, name, "upload", s.transport.WriteTree(ctx, h, p, entries))
	s.finish("upload", name, started, err, usage{in: treeBytes(entries)})
	return err
}

// Text rejects binary data rather than silently replacing invalid UTF-8 in JSON.
func Text(data []byte) (string, error) {
	if !utf8.Valid(data) {
		return "", fmt.Errorf("file is not UTF-8 text; binary MCP reads are unsupported")
	}
	return string(data), nil
}

// TextRange decodes a slice cut at arbitrary byte offsets. It drops a partial
// UTF-8 character at either edge and returns the adjusted start offset, so the
// next slice can begin at offset+len(text) without losing bytes.
func TextRange(r transport.FileRange) (string, int64, error) {
	data, offset := r.Data, r.Offset
	if offset > 0 {
		for i := 0; i < utf8.UTFMax-1 && len(data) > 0 && !utf8.RuneStart(data[0]); i++ {
			data, offset = data[1:], offset+1
		}
	}
	if r.Offset+int64(len(r.Data)) < r.Size {
		for i := 1; i <= utf8.UTFMax && i <= len(data); i++ {
			if utf8.RuneStart(data[len(data)-i]) {
				if !utf8.FullRune(data[len(data)-i:]) {
					data = data[:len(data)-i]
				}
				break
			}
		}
	}
	text, err := Text(data)
	return text, offset, err
}

// TimeoutMillis validates a wire timeout before converting it to a duration.
func TimeoutMillis(ms int64) (time.Duration, error) {
	if ms < 0 || ms > int64((1<<63-1)/time.Millisecond) {
		return 0, fmt.Errorf("timeout_ms is out of range")
	}
	return time.Duration(ms) * time.Millisecond, nil
}
