// Package ssh implements a verified SSH transport whose connections are pooled
// and reused across operations. Connections are keyed by host and all
// authentication material, health-checked before reuse, and bounded by idle
// limits and lifetime.
package ssh

import (
	"ash/internal/host"
	"ash/internal/transport"
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"github.com/pkg/sftp"
	gossh "golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
	"golang.org/x/crypto/ssh/knownhosts"
	"io/fs"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
)

type Transport struct {
	knownHostsPath string
	pool           *resourcePool
	dial           func(context.Context, host.Host) (*sshResource, error)
	// dialOverride, when set by tests, replaces the TCP dial and SSH
	// handshake so operations run against an in-process transport.
	dialOverride func(ctx context.Context, h host.Host) (*gossh.Client, func(), error)
	// newSFTPDial, when set by tests, supplies an SFTP client directly,
	// bypassing connection setup entirely.
	newSFTPDial func(ctx context.Context, h host.Host) (*sftp.Client, func(), error)
}

func New(knownHostsPath string) (*Transport, error) {
	t := &Transport{
		knownHostsPath: knownHostsPath,
		pool:           newResourcePool(DefaultMaxConnections, DefaultMaxIdlePerHost, DefaultIdleLifetime, nil),
	}
	t.setDial(t.dialSSH)
	return t, nil
}

// Close shuts down the connection pool, closing every idle connection. Active
// operations keep their own connection until they finish.
func (t *Transport) Close() { t.pool.Close() }

// setDial replaces the dial implementation. It exists for tests that must
// observe which exact resource instance enters the pool.
func (t *Transport) setDial(fn func(context.Context, host.Host) (*sshResource, error)) { t.dial = fn }

// keyFor derives the reuse boundary for a host. Host, authentication material,
// agent, host-key alias, and trust file must all match.
func keyFor(h host.Host, knownHostsPath string) connKey {
	return connKey{
		address:      h.Address,
		port:         h.Port,
		user:         h.User,
		identity:     h.Identity,
		identities:   strings.Join(h.Identities, "\x00"),
		agent:        h.AgentSocket,
		hostKeyAlias: h.HostKeyAlias,
		knownHosts:   strings.Join(trustFiles(h, knownHostsPath), "\x00"),
	}
}

// trustFiles returns the known_hosts candidates for a host: those OpenSSH
// resolved for its alias, or the transport default.
func trustFiles(h host.Host, knownHostsPath string) []string {
	if len(h.KnownHostsFiles) > 0 {
		return h.KnownHostsFiles
	}
	return []string{knownHostsPath}
}

// sshResource adapts a pooled SSH client to the pool's resource contract. It
// owns the connection and the per-dial lifecycle (agent socket and context
// stop); close releases both exactly once.
type sshResource struct {
	client    *gossh.Client
	lifecycle resourceLifecycle
	closeOnce sync.Once
	closeErr  error
	// sftp is the connection's SFTP session, opened on first file operation
	// and reused while it lives; sftpDone closes when that session ends.
	sftp     *sftp.Client
	sftpDone chan struct{}
}

// sftpClient returns the connection's SFTP session, replacing one that has
// ended. The pool hands a resource to one operation at a time, so the session
// is never shared concurrently.
func (r *sshResource) sftpClient() (*sftp.Client, error) {
	if r.sftp != nil {
		select {
		case <-r.sftpDone:
			r.sftp.Close()
			r.sftp = nil
		default:
			return r.sftp, nil
		}
	}
	fs, err := sftp.NewClient(r.client)
	if err != nil {
		return nil, err
	}
	done := make(chan struct{})
	go func() { fs.Wait(); close(done) }()
	r.sftp, r.sftpDone = fs, done
	return fs, nil
}

// healthCheck sends one keepalive probe. The provided context always carries a
// deadline set by the pool, and this probe honors it: gossh.SendRequest blocks
// on the connection, so the probe is aborted by closing the connection when
// the deadline or the caller's cancellation fires first.
func (r *sshResource) healthCheck(ctx context.Context) bool {
	if r.client == nil {
		return false
	}
	type probeResult struct {
		err error
	}
	probe := make(chan probeResult, 1)
	go func() {
		_, _, err := r.client.SendRequest("keepalive@openssh.com", true, nil)
		probe <- probeResult{err: err}
	}()
	select {
	case result := <-probe:
		return result.err == nil
	case <-ctx.Done():
		// Bound the probe: a half-open connection would otherwise block
		// forever. Closing the connection unblocks the in-flight request.
		_ = r.client.Close()
		return false
	}
}

func (r *sshResource) setLifecycle(lc resourceLifecycle) { r.lifecycle = lc }

// close tears down the connection and its per-dial lifecycle exactly once,
// even when called from several eviction paths or after a failed health
// check already closed the underlying connection. The lifecycle stop runs
// before cleanup so the context watcher is released before its socket closes.
func (r *sshResource) close() error {
	r.closeOnce.Do(func() {
		if r.lifecycle.stop != nil {
			r.lifecycle.stop()
		}
		if r.sftp != nil {
			r.sftp.Close()
		}
		if r.client != nil {
			r.closeErr = r.client.Close()
		}
		if r.lifecycle.cleanup != nil {
			r.lifecycle.cleanup()
		}
		r.lifecycle = resourceLifecycle{}
	})
	return r.closeErr
}

// errIdentityMissing reports an identity file that does not exist and is
// allowed to be skipped.
var errIdentityMissing = errors.New("identity file does not exist")

// selectIdentities returns the identity paths to load and whether they are
// explicitly configured in ASH. Identities resolved from `ssh -G` include
// OpenSSH's default candidate paths regardless of existence, so a missing one
// must be skipped the way OpenSSH skips it; an explicit ASH identity is a
// deliberate instruction and stays strict.
func selectIdentities(h host.Host) (paths []string, explicit bool) {
	if len(h.Identities) == 0 && h.Identity != "" {
		return []string{h.Identity}, true
	}
	return h.Identities, false
}

// loadIdentityFile reads and parses one identity file. When missingOK is set,
// a file that does not exist yields errIdentityMissing instead of an error.
func loadIdentityFile(path string, missingOK bool) (gossh.Signer, error) {
	key, err := os.ReadFile(path)
	if err != nil {
		if missingOK && errors.Is(err, fs.ErrNotExist) {
			return nil, errIdentityMissing
		}
		return nil, fmt.Errorf("%w: read identity: %v", transport.ErrAuthentication, err)
	}
	signer, err := gossh.ParsePrivateKey(key)
	if err != nil {
		return nil, fmt.Errorf("%w: parse identity: %v", transport.ErrAuthentication, err)
	}
	return signer, nil
}

func (t *Transport) knownHosts(h host.Host) (gossh.HostKeyCallback, error) {
	// Like OpenSSH, read every candidate that exists; a missing one is
	// skipped, but at least one trust file is required.
	candidates := trustFiles(h, t.knownHostsPath)
	files := make([]string, 0, len(candidates))
	for _, candidate := range candidates {
		path, err := expandHome(candidate)
		if err != nil {
			return nil, fmt.Errorf("%w: load known_hosts: %v", transport.ErrHostKey, err)
		}
		if _, err := os.Stat(path); err == nil {
			files = append(files, path)
		}
	}
	if len(files) == 0 {
		return nil, fmt.Errorf("%w: load known_hosts: no file found at %s", transport.ErrHostKey, strings.Join(candidates, ", "))
	}
	callback, err := knownhosts.New(files...)
	if err != nil {
		return nil, fmt.Errorf("%w: load known_hosts: %v", transport.ErrHostKey, err)
	}
	return func(address string, remote net.Addr, key gossh.PublicKey) error {
		if err := callback(address, remote, key); err != nil {
			return fmt.Errorf("%w: %s is not trusted; verify it using OpenSSH and update known_hosts: %w", transport.ErrHostKey, address, err)
		}
		return nil
	}, nil
}

func operationError(ctx context.Context, err error) error {
	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		return fmt.Errorf("%w: %w", transport.ErrTimeout, ctx.Err())
	}
	if ctx.Err() != nil {
		return ctx.Err()
	}
	return err
}

// expandHome resolves a leading ~ against the local home directory.
func expandHome(path string) (string, error) {
	if path == "~" || strings.HasPrefix(path, "~/") {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", err
		}
		if path == "~" {
			return home, nil
		}
		return filepath.Join(home, path[2:]), nil
	}
	return path, nil
}

// connect returns a pooled or freshly dialed client. The returned release
// function returns the connection to the pool for reuse; it never closes a
// healthy connection. Connection lifetime is intentionally independent of the
// per-operation context. The health check of a pooled candidate runs with the
// caller's context, bounded by the pool's timeout, outside the pool mutex.
func (t *Transport) connect(ctx context.Context, h host.Host) (*gossh.Client, func(), error) {
	if err := ctx.Err(); err != nil {
		return nil, nil, operationError(ctx, err)
	}
	if t.dialOverride != nil {
		return t.dialOverride(ctx, h)
	}
	res, release, err := t.claim(ctx, h)
	if err != nil {
		return nil, nil, err
	}
	return res.client, release, nil
}

// claim returns a pooled or freshly dialed resource and the function that
// returns it to the pool.
func (t *Transport) claim(ctx context.Context, h host.Host) (*sshResource, func(), error) {
	key := keyFor(h, t.knownHostsPath)
	if res, ok := t.pool.get(ctx, key); ok {
		return res.(*sshResource), func() { t.pool.put(key, res) }, nil
	}
	if err := t.pool.reserve(ctx); err != nil {
		return nil, nil, operationError(ctx, err)
	}
	res, err := t.dial(ctx, h)
	if err != nil {
		t.pool.releaseSlot()
		return nil, nil, err
	}
	return res, func() { t.pool.put(key, res) }, nil
}

// dialSSH establishes a fresh, verified connection and returns the resource
// that owns it, lifecycle included. The caller (connect) pools this exact
// resource. Cleanup for a failed dial happens inside dialSSH; a returned
// resource is only ever closed through the pool.
func (t *Transport) dialSSH(ctx context.Context, h host.Host) (*sshResource, error) {
	hostKey, err := t.knownHosts(h)
	if err != nil {
		return nil, err
	}
	var agentConn net.Conn
	var stopAgent func() bool
	cleanupAgent := func() {
		if stopAgent != nil {
			stopAgent()
		}
		if agentConn != nil {
			agentConn.Close()
		}
	}
	var allSigners []gossh.Signer
	// An explicit OpenSSH IdentityAgent (including "none") overrides the
	// environment; otherwise use SSH_AUTH_SOCK.
	agentSocket := h.AgentSocket
	if agentSocket == "" {
		agentSocket = os.Getenv("SSH_AUTH_SOCK")
	}
	if agentSocket != "" && agentSocket != "none" {
		conn, err := (&net.Dialer{}).DialContext(ctx, "unix", agentSocket)
		if err == nil {
			agentConn = conn
			stopAgent = context.AfterFunc(ctx, func() { conn.Close() })
			signers, signErr := agent.NewClient(conn).Signers()
			if signErr == nil && len(signers) > 0 {
				allSigners = append(allSigners, signers...)
			}
		}
	}
	identities, strict := selectIdentities(h)
	for _, identity := range identities {
		path, err := expandHome(identity)
		if err != nil {
			cleanupAgent()
			return nil, err
		}
		signer, err := loadIdentityFile(path, !strict)
		if err != nil {
			if errors.Is(err, errIdentityMissing) {
				continue
			}
			cleanupAgent()
			return nil, err
		}
		allSigners = append(allSigners, signer)
	}
	if ctx.Err() != nil {
		cleanupAgent()
		return nil, operationError(ctx, ctx.Err())
	}
	if len(allSigners) == 0 {
		cleanupAgent()
		return nil, fmt.Errorf("%w: no SSH agent keys or identity available", transport.ErrAuthentication)
	}
	port := h.Port
	if port == 0 {
		port = 22
	}
	dialAddress := net.JoinHostPort(h.Address, strconv.Itoa(port))
	// HostKeyAlias changes only host-key lookup, not the dialed address.
	verifyAddress := dialAddress
	if h.HostKeyAlias != "" {
		verifyAddress = net.JoinHostPort(h.HostKeyAlias, strconv.Itoa(port))
	}
	conn, err := (&net.Dialer{}).DialContext(ctx, "tcp", dialAddress)
	if err != nil {
		cleanupAgent()
		return nil, operationError(ctx, fmt.Errorf("connect to host %q: %w", h.Name, err))
	}
	// The TCP connection outlives the operation context when pooled, so it
	// must not be stopped by that context. HandshakeAbort cancels a handshake
	// that would otherwise outstay the caller's deadline; it is consumed
	// before the connection enters the pool.
	handshakeDone := make(chan struct{})
	stopHandshake := context.AfterFunc(ctx, func() {
		select {
		case <-handshakeDone:
		default:
			conn.Close()
		}
	})
	cleanup := func() { conn.Close(); cleanupAgent() }
	algorithms := preferredHostKeyAlgorithms(hostKey, verifyAddress, conn.RemoteAddr())
	sshConn, chans, reqs, err := gossh.NewClientConn(conn, verifyAddress, &gossh.ClientConfig{User: h.User, Auth: []gossh.AuthMethod{gossh.PublicKeys(allSigners...)}, HostKeyCallback: hostKey, HostKeyAlgorithms: algorithms})
	close(handshakeDone)
	if err != nil {
		stopHandshake()
		cleanup()
		err = operationError(ctx, err)
		if strings.Contains(err.Error(), "unable to authenticate") {
			err = fmt.Errorf("%w: %v", transport.ErrAuthentication, err)
		}
		return nil, err
	}
	stopHandshake()
	client := gossh.NewClient(sshConn, chans, reqs)
	// The per-dial resources (agent socket) belong to the long-lived
	// connection and are released exactly once when it is finally closed
	// through sshResource.close, from any eviction or shutdown path.
	res := &sshResource{client: client}
	res.setLifecycle(resourceLifecycle{stop: stopAgent, cleanup: cleanupAgent})
	return res, nil
}

// preferredHostKeyAlgorithms asks the known_hosts matcher for this host's keys
// using a deliberately nonmatching probe. This preserves its hashed-name, port,
// wildcard, and revocation semantics. Actual server keys are still verified by
// the unchanged callback during the handshake.
func preferredHostKeyAlgorithms(callback gossh.HostKeyCallback, address string, remote net.Addr) []string {
	probe, _ := gossh.NewPublicKey(ed25519.PublicKey(make([]byte, ed25519.PublicKeySize)))
	var keyError *knownhosts.KeyError
	err := callback(address, remote, probe)
	if !errors.As(err, &keyError) || len(keyError.Want) == 0 {
		return nil
	}
	trusted := make(map[string]bool)
	for _, known := range keyError.Want {
		trusted[known.Key.Type()] = true
		if known.Key.Type() == gossh.KeyAlgoRSA {
			trusted[gossh.KeyAlgoRSASHA256] = true
			trusted[gossh.KeyAlgoRSASHA512] = true
		}
	}
	supported := gossh.SupportedAlgorithms().HostKeys
	ordered := make([]string, 0, len(supported))
	for _, algorithm := range supported {
		if trusted[algorithm] {
			ordered = append(ordered, algorithm)
		}
	}
	for _, algorithm := range supported {
		if !trusted[algorithm] {
			ordered = append(ordered, algorithm)
		}
	}
	return ordered
}
