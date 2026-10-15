package integration

import (
	"ash/internal/host"
	"ash/internal/transport"
	sshtransport "ash/internal/transport/ssh"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	sdk "github.com/modelcontextprotocol/go-sdk/mcp"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
	"golang.org/x/crypto/ssh/knownhosts"
	"net"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

func key(t *testing.T, filename string) (ed25519.PrivateKey, ssh.PublicKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	block, err := ssh.MarshalPrivateKey(priv, "")
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(filename, pem.EncodeToMemory(block), 0600); err != nil {
		t.Fatal(err)
	}
	public, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	return priv, public
}

// TestOpenSSH uses an isolated local OpenSSH daemon, never a configured remote host.
// Enable with ASH_INTEGRATION=1; sshd must be available and runnable by the current user.
func TestOpenSSH(t *testing.T) {
	if os.Getenv("ASH_INTEGRATION") != "1" {
		t.Skip("set ASH_INTEGRATION=1 to run the isolated OpenSSH fixture")
	}
	sshd, err := exec.LookPath("sshd")
	if err != nil {
		sshd = "/usr/sbin/sshd"
	}
	if _, err = os.Stat(sshd); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	identity := filepath.Join(dir, "identity")
	priv, pub := key(t, identity)
	_, serverKey := key(t, filepath.Join(dir, "host_key"))

	ecdsaPrivate, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ecdsaBlock, err := ssh.MarshalPrivateKey(ecdsaPrivate, "")
	if err != nil {
		t.Fatal(err)
	}
	ecdsaPath := filepath.Join(dir, "host_key_ecdsa")
	if err = os.WriteFile(ecdsaPath, pem.EncodeToMemory(ecdsaBlock), 0600); err != nil {
		t.Fatal(err)
	}
	auth := filepath.Join(dir, "authorized_keys")
	os.WriteFile(auth, ssh.MarshalAuthorizedKey(pub), 0600)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	listener.Close()
	current, err := user.Current()
	if err != nil {
		t.Fatal(err)
	}
	config := fmt.Sprintf("Port %d\nListenAddress 127.0.0.1\nHostKey %s\nPidFile %s\nAuthorizedKeysFile %s\nStrictModes no\nPasswordAuthentication no\nKbdInteractiveAuthentication no\nUsePAM no\nPermitRootLogin yes\nSubsystem sftp internal-sftp\n", port, filepath.Join(dir, "host_key"), filepath.Join(dir, "pid"), auth)
	config += "HostKey " + ecdsaPath + "\n"
	configPath := filepath.Join(dir, "sshd_config")
	os.WriteFile(configPath, []byte(config), 0600)
	logPath := filepath.Join(dir, "sshd.log")
	cmd := exec.Command(sshd, "-D", "-f", configPath, "-E", logPath)
	if err = cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { cmd.Process.Kill(); cmd.Wait() })
	address := net.JoinHostPort("127.0.0.1", strconv.Itoa(port))
	deadline := time.Now().Add(5 * time.Second)
	for {
		c, e := net.DialTimeout("tcp", address, 100*time.Millisecond)
		if e == nil {
			c.Close()
			break
		}
		if time.Now().After(deadline) {
			log, _ := os.ReadFile(logPath)
			t.Fatalf("sshd did not start: %s", log)
		}
		time.Sleep(20 * time.Millisecond)
	}
	known := filepath.Join(dir, "known_hosts")
	os.WriteFile(known, []byte(knownhosts.Line([]string{address}, serverKey)+"\n"), 0600)
	tr, err := sshtransport.New(known)
	if err != nil {
		t.Fatal(err)
	}
	h := host.Host{Name: "fixture", Address: "127.0.0.1", Port: port, User: current.Username, Identity: identity}
	t.Setenv("SSH_AUTH_SOCK", "")
	t.Run("exec", func(t *testing.T) {
		r, e := tr.Exec(context.Background(), h, transport.ExecRequest{Command: `printf '%s' "$VALUE"; printf error >&2; exit 7`, Cwd: dir, Env: map[string]string{"VALUE": "a ' $(echo no)"}})
		if e != nil || r.ExitCode != 7 || r.Stdout != "a ' $(echo no)" || r.Stderr != "error" {
			t.Fatalf("%+v %v", r, e)
		}
	})
	t.Run("files", func(t *testing.T) {
		p := filepath.Join(dir, "file ' ;$")
		if e := tr.Write(context.Background(), h, p, []byte("hello")); e != nil {
			t.Fatal(e)
		}
		data, e := tr.Read(context.Background(), h, p)
		if e != nil || string(data) != "hello" {
			t.Fatalf("%q %v", data, e)
		}
		info, e := tr.Stat(context.Background(), h, p)
		if e != nil || info.Size != 5 || info.IsDir {
			t.Fatalf("%+v %v", info, e)
		}
		if e = tr.Write(context.Background(), h, p, []byte("x")); e != nil {
			t.Fatal(e)
		}
		data, e = tr.Read(context.Background(), h, p)
		if e != nil || string(data) != "x" {
			t.Fatalf("%q %v", data, e)
		}
		os.WriteFile(p, make([]byte, transport.MaxReadSize+1), 0600)
		if _, e = tr.Read(context.Background(), h, p); !errors.Is(e, transport.ErrTooLarge) {
			t.Fatal(e)
		}
	})
	t.Run("tree", func(t *testing.T) {
		root := filepath.Join(dir, "tree")
		os.MkdirAll(filepath.Join(root, "a", "b"), 0755)
		os.WriteFile(filepath.Join(root, "a", "b", "c.txt"), []byte("deep"), 0644)
		os.WriteFile(filepath.Join(root, "top.txt"), []byte("top"), 0644)
		os.Symlink(filepath.Join(root, "top.txt"), filepath.Join(root, "link"))
		entries, e := tr.List(context.Background(), h, root)
		if e != nil || len(entries) < 3 || entries[0].Name != "a" {
			t.Fatalf("list: %+v %v", entries, e)
		}
		if e = tr.Mkdir(context.Background(), h, filepath.Join(root, "new")); e != nil {
			t.Fatal(e)
		}
		if e = tr.Mkdir(context.Background(), h, filepath.Join(root, "missing", "child")); e == nil {
			t.Fatal("mkdir created missing parents")
		}
		if e = tr.Rename(context.Background(), h, filepath.Join(root, "new"), filepath.Join(root, "moved")); e != nil {
			t.Fatal(e)
		}
		if e = tr.Remove(context.Background(), h, filepath.Join(root, "moved")); e != nil {
			t.Fatal(e)
		}
		target := filepath.Join(root, "atomic.txt")
		if e = tr.Write(context.Background(), h, target, []byte("old")); e != nil {
			t.Fatal(e)
		}
		if e = tr.AtomicWrite(context.Background(), h, target, []byte("new")); e != nil {
			t.Fatal(e)
		}
		if data, e := tr.Read(context.Background(), h, target); e != nil || string(data) != "new" {
			t.Fatalf("atomic %q %v", data, e)
		}
		tree, e := tr.ReadTree(context.Background(), h, root)
		if e != nil {
			t.Fatal(e)
		}
		for _, entry := range tree {
			if strings.Contains(entry.Path, "link") {
				t.Fatalf("followed symlink: %+v", entry)
			}
		}
		upload := filepath.Join(dir, "upload")
		if e = tr.WriteTree(context.Background(), h, upload, []transport.TreeEntry{{Path: "x", IsDir: true}, {Path: "x/y.txt", Data: []byte("hi")}}); e != nil {
			t.Fatal(e)
		}
		if data, e := tr.Read(context.Background(), h, filepath.Join(upload, "x", "y.txt")); e != nil || string(data) != "hi" {
			t.Fatalf("upload %q %v", data, e)
		}
	})
	t.Run("timeout", func(t *testing.T) {
		_, e := tr.Exec(context.Background(), h, transport.ExecRequest{Command: "sleep 10", Timeout: 100 * time.Millisecond})
		if !errors.Is(e, transport.ErrTimeout) {
			t.Fatal(e)
		}
	})
	t.Run("cancel", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		time.AfterFunc(100*time.Millisecond, cancel)
		_, e := tr.Exec(ctx, h, transport.ExecRequest{Command: "sleep 10"})
		if !errors.Is(e, context.Canceled) {
			t.Fatal(e)
		}
	})
	t.Run("unknown host", func(t *testing.T) {
		empty := filepath.Join(dir, "empty_known_hosts")
		os.WriteFile(empty, nil, 0600)
		untrusted, e := sshtransport.New(empty)
		if e != nil {
			t.Fatal(e)
		}
		_, e = untrusted.Exec(context.Background(), h, transport.ExecRequest{Command: "true"})
		if !errors.Is(e, transport.ErrHostKey) {
			t.Fatal(e)
		}
	})

	t.Run("changed trusted key", func(t *testing.T) {
		_, wrong := key(t, filepath.Join(dir, "wrong_host_key"))
		trust := filepath.Join(dir, "wrong_known_hosts")
		os.WriteFile(trust, []byte(knownhosts.Line([]string{address}, wrong)+"\n"), 0600)
		client, e := sshtransport.New(trust)
		if e != nil {
			t.Fatal(e)
		}
		_, e = client.Exec(context.Background(), h, transport.ExecRequest{Command: "true"})
		if !errors.Is(e, transport.ErrHostKey) {
			t.Fatal(e)
		}
	})
	t.Run("bad identity", func(t *testing.T) {
		bad := h
		bad.Identity = filepath.Join(dir, "wrong_key")
		key(t, bad.Identity)
		_, e := tr.Exec(context.Background(), bad, transport.ExecRequest{Command: "true"})
		if !errors.Is(e, transport.ErrAuthentication) {
			t.Fatal(e)
		}
	})
	t.Run("output limit", func(t *testing.T) {
		r, e := tr.Exec(context.Background(), h, transport.ExecRequest{Command: "head -c 8388700 /dev/zero"})
		if e != nil || len(r.Stdout) != transport.MaxOutputSize || !r.StdoutTruncated {
			t.Fatalf("size=%d truncated=%v error=%v", len(r.Stdout), r.StdoutTruncated, e)
		}
	})
	t.Run("stalled handshake", func(t *testing.T) {
		l, e := net.Listen("tcp", "127.0.0.1:0")
		if e != nil {
			t.Fatal(e)
		}
		defer l.Close()
		go func() {
			c, e := l.Accept()
			if e == nil {
				defer c.Close()
				var b [1]byte
				for {
					if _, e = c.Read(b[:]); e != nil {
						return
					}
				}
			}
		}()
		stalled := h
		stalled.Port = l.Addr().(*net.TCPAddr).Port
		_, e = tr.Exec(context.Background(), stalled, transport.ExecRequest{Command: "true", Timeout: 100 * time.Millisecond})
		if !errors.Is(e, transport.ErrTimeout) {
			t.Fatal(e)
		}
	})
	t.Run("MCP remote operations", func(t *testing.T) {
		binary := filepath.Join(dir, "ash")
		build := exec.Command("go", "build", "-o", binary, "../cmd/ash")
		if out, e := build.CombinedOutput(); e != nil {
			t.Fatalf("build: %s %v", out, e)
		}
		os.Mkdir(filepath.Join(dir, ".ssh"), 0700)
		trust, _ := os.ReadFile(known)
		os.WriteFile(filepath.Join(dir, ".ssh", "known_hosts"), trust, 0600)
		config := filepath.Join(dir, "ash.toml")
		os.WriteFile(config, []byte(fmt.Sprintf("[hosts.fixture]\naddress='127.0.0.1'\nport=%d\nuser='%s'\nidentity='%s'\n[hosts.fixture.policy]\nexec=true\nread=true\nwrite=true\n", port, current.Username, identity)), 0600)
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		command := exec.Command(binary, "--config", config, "mcp")
		command.Env = append(os.Environ(), "HOME="+dir)
		command.Stderr = os.Stderr
		client := sdk.NewClient(&sdk.Implementation{Name: "ssh-integration", Version: "1"}, nil)
		session, e := client.Connect(ctx, &sdk.CommandTransport{Command: command}, nil)
		if e != nil {
			t.Fatal(e)
		}
		defer session.Close()
		call := func(name string, args map[string]any) map[string]any {
			t.Helper()
			result, e := session.CallTool(ctx, &sdk.CallToolParams{Name: name, Arguments: args})
			if e != nil || result.IsError {
				t.Fatalf("%s: %+v %v", name, result, e)
			}
			data, e := json.Marshal(result.StructuredContent)
			if e != nil {
				t.Fatal(e)
			}
			var value map[string]any
			if e = json.Unmarshal(data, &value); e != nil {
				t.Fatal(e)
			}
			return value
		}
		value := call("ash_exec", map[string]any{"host": "fixture", "command": "printf mcp; exit 3"})
		if value["stdout"] != "mcp" || value["exit_code"] != float64(3) {
			t.Fatal(value)
		}
		p := filepath.Join(dir, "mcp.txt")
		call("ash_write", map[string]any{"host": "fixture", "path": p, "content": "hello from MCP"})
		value = call("ash_read", map[string]any{"host": "fixture", "path": p})
		if value["content"] != "hello from MCP" {
			t.Fatal(value)
		}
		value = call("ash_stat", map[string]any{"host": "fixture", "path": p})
		if value["size"] != float64(14) {
			t.Fatal(value)
		}
	})

	t.Run("agent", func(t *testing.T) {
		socket := filepath.Join(dir, "agent.sock")
		l, e := net.Listen("unix", socket)
		if e != nil {
			t.Fatal(e)
		}
		defer l.Close()
		ring := agent.NewKeyring()
		ring.Add(agent.AddedKey{PrivateKey: priv})
		go func() {
			for {
				c, e := l.Accept()
				if e != nil {
					return
				}
				go func() { defer c.Close(); agent.ServeAgent(ring, c) }()
			}
		}()
		t.Setenv("SSH_AUTH_SOCK", socket)
		agentHost := h
		agentHost.Identity = ""
		r, e := tr.Exec(context.Background(), agentHost, transport.ExecRequest{Command: "printf agent"})
		if e != nil || strings.TrimSpace(r.Stdout) != "agent" {
			t.Fatalf("%+v %v", r, e)
		}
		ring.RemoveAll()
		_, wrong, _ := ed25519.GenerateKey(rand.Reader)
		ring.Add(agent.AddedKey{PrivateKey: wrong})
		r, e = tr.Exec(context.Background(), h, transport.ExecRequest{Command: "printf fallback"})
		if e != nil || r.Stdout != "fallback" {
			t.Fatalf("identity fallback: %+v %v", r, e)
		}
	})
}
