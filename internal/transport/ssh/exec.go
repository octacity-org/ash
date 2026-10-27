package ssh

import (
	"ash/internal/host"
	"ash/internal/transport"
	"bytes"
	"context"
	"errors"
	"fmt"
	gossh "golang.org/x/crypto/ssh"
	"regexp"
	"sort"
	"strings"
	"time"
)

// QuoteShell quotes one literal POSIX shell word.
func QuoteShell(value string) string { return "'" + strings.ReplaceAll(value, "'", `'"'"'`) + "'" }

var envName = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

// buildPreamble renders environment exports and the optional cwd change shared
// by shell-code and argv execution.
func buildPreamble(req transport.ExecRequest) (string, error) {
	if strings.ContainsRune(req.Cwd, 0) {
		return "", fmt.Errorf("cwd must not contain NUL")
	}
	var b strings.Builder
	keys := make([]string, 0, len(req.Env))
	for k := range req.Env {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		v := req.Env[k]
		if !envName.MatchString(k) || strings.ContainsRune(v, 0) {
			return "", fmt.Errorf("invalid environment variable %q", k)
		}
		fmt.Fprintf(&b, "export %s=%s\n", k, QuoteShell(v))
	}
	if req.Cwd != "" {
		cwd := QuoteShell(req.Cwd)
		if req.Cwd == "~" {
			cwd = `"$HOME"`
		} else if strings.HasPrefix(req.Cwd, "~/") {
			cwd = `"$HOME"/` + QuoteShell(req.Cwd[2:])
		}
		fmt.Fprintf(&b, "cd -- %s || exit\n", cwd)
	}
	return b.String(), nil
}

func buildCommand(req transport.ExecRequest) (string, error) {
	if strings.ContainsRune(req.Command, 0) {
		return "", fmt.Errorf("command must not contain NUL")
	}
	preamble, err := buildPreamble(req)
	if err != nil {
		return "", err
	}
	return preamble + req.Command, nil
}

// buildArgv quotes structured arguments as literal POSIX words. No shell
// interpretation is possible, so program restrictions cannot be bypassed.
func buildArgv(req transport.ExecRequest) (string, error) {
	if len(req.Argv) == 0 {
		return "", fmt.Errorf("argv must not be empty")
	}
	preamble, err := buildPreamble(req)
	if err != nil {
		return "", err
	}
	parts := make([]string, 0, len(req.Argv))
	for _, arg := range req.Argv {
		if strings.ContainsRune(arg, 0) {
			return "", fmt.Errorf("argv must not contain NUL")
		}
		parts = append(parts, QuoteShell(arg))
	}
	return preamble + strings.Join(parts, " "), nil
}

type limitedBuffer struct {
	buffer    bytes.Buffer
	limit     int
	truncated bool
}

func (b *limitedBuffer) Len() int       { return b.buffer.Len() }
func (b *limitedBuffer) String() string { return b.buffer.String() }

func (b *limitedBuffer) Write(p []byte) (int, error) {
	n := len(p)
	remaining := b.limit - b.Len()
	if n > remaining {
		b.truncated = true
		p = p[:remaining]
	}
	b.buffer.Write(p)
	return n, nil
}
func execCommand(req transport.ExecRequest) (string, error) {
	if len(req.Argv) > 0 {
		return buildArgv(req)
	}
	return buildCommand(req)
}

func (t *Transport) Exec(ctx context.Context, h host.Host, req transport.ExecRequest) (result transport.ExecResult, err error) {
	started := time.Now()
	defer func() { result.Duration = time.Since(started) }()
	command, err := execCommand(req)
	if err != nil {
		return result, err
	}
	timeout := req.Timeout
	if timeout <= 0 {
		timeout = transport.DefaultExecTimeout
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	client, cleanup, err := t.connect(ctx, h)
	if err != nil {
		return result, err
	}
	defer cleanup()
	session, err := client.NewSession()
	if err != nil {
		return result, operationError(ctx, err)
	}
	defer session.Close()
	if req.StdinSet {
		if len(req.Stdin) > transport.MaxExecInputSize {
			return result, transport.ErrInputTooLarge
		}
		// A bytes.Reader sends EOF after the payload, so the remote stdin stream
		// closes even when the process expects input until end of file.
		session.Stdin = bytes.NewReader(req.Stdin)
	}
	limit := transport.MaxOutputSize
	if req.MaxOutput > 0 && req.MaxOutput < limit {
		limit = req.MaxOutput
	}
	stdout := limitedBuffer{limit: limit}
	stderr := limitedBuffer{limit: limit}
	session.Stdout = &stdout
	session.Stderr = &stderr
	// Close the channel when the context ends so a stalled stdin write or a
	// hung remote process cannot keep Run blocked past cancellation.
	stop := context.AfterFunc(ctx, func() { session.Close() })
	defer stop()
	err = session.Run(command)
	result.Stdout = stdout.String()
	result.Stderr = stderr.String()
	result.StdoutTruncated = stdout.truncated
	result.StderrTruncated = stderr.truncated
	return exitResult(ctx, result, err)
}

// exitResult turns a remote exit status into a result rather than an error.
func exitResult(ctx context.Context, result transport.ExecResult, err error) (transport.ExecResult, error) {
	if ctx.Err() != nil {
		return result, operationError(ctx, err)
	}
	var exit *gossh.ExitError
	if errors.As(err, &exit) {
		result.ExitCode = exit.ExitStatus()
		return result, nil
	}
	return result, err
}

// ExecStream runs a command with its standard streams connected to stdio. The
// caller's context bounds the whole run; cancelling it closes the session.
func (t *Transport) ExecStream(ctx context.Context, h host.Host, req transport.ExecRequest, stdio transport.Stdio) (result transport.ExecResult, err error) {
	started := time.Now()
	defer func() { result.Duration = time.Since(started) }()
	command, err := execCommand(req)
	if err != nil {
		return result, err
	}
	client, cleanup, err := t.connect(ctx, h)
	if err != nil {
		return result, err
	}
	defer cleanup()
	session, err := client.NewSession()
	if err != nil {
		return result, operationError(ctx, err)
	}
	defer session.Close()
	session.Stdout = stdio.Stdout
	session.Stderr = stdio.Stderr
	// x/crypto closes its stdin pipe once the exit status arrives, so Run
	// returns when the remote command exits even if local stdin stays open.
	// Local EOF closes the remote stdin.
	if stdio.Stdin != nil {
		session.Stdin = stdio.Stdin
	}
	stop := context.AfterFunc(ctx, func() { session.Close() })
	defer stop()
	return exitResult(ctx, result, session.Run(command))
}
