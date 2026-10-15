package mcp

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"testing"
	"time"

	sdk "github.com/modelcontextprotocol/go-sdk/mcp"

	"ash/internal/host"
	"ash/internal/policy"
	"ash/internal/service"
	"ash/internal/shell"
	"ash/internal/transport"
)

func TestToolsAndDeniedExec(t *testing.T) {
	ctx := context.Background()
	server := New(service.New(host.New(map[string]host.Host{"h": {}}), nil), nil)
	st, ct := sdk.NewInMemoryTransports()
	ss, err := server.Connect(ctx, st, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer ss.Close()
	client := sdk.NewClient(&sdk.Implementation{Name: "test", Version: "1"}, nil)
	cs, err := client.Connect(ctx, ct, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer cs.Close()
	list, err := cs.ListTools(ctx, nil)
	if err != nil || len(list.Tools) != 18 {
		t.Fatalf("%+v %v", list, err)
	}
	res, err := cs.CallTool(ctx, &sdk.CallToolParams{Name: "ash_hosts", Arguments: map[string]any{}})
	if err != nil || res.IsError {
		t.Fatalf("%+v %v", res, err)
	}
	res, err = cs.CallTool(ctx, &sdk.CallToolParams{Name: "ash_exec", Arguments: map[string]any{"host": "h", "command": "true"}})
	if err != nil || !res.IsError {
		t.Fatalf("%+v %v", res, err)
	}
}

type cancelTransport struct {
	transport.Transport
	started  chan struct{}
	canceled chan struct{}
}

func (f *cancelTransport) Exec(ctx context.Context, _ host.Host, _ transport.ExecRequest) (transport.ExecResult, error) {
	close(f.started)
	<-ctx.Done()
	close(f.canceled)
	return transport.ExecResult{}, ctx.Err()
}

type argvTransport struct {
	transport.Transport
	argv []string
}

func (f *argvTransport) Exec(_ context.Context, _ host.Host, req transport.ExecRequest) (transport.ExecResult, error) {
	f.argv = req.Argv
	return transport.ExecResult{}, nil
}

func TestExecArgvTool(t *testing.T) {
	ctx := context.Background()
	tr := new(argvTransport)
	server := New(service.New(host.New(map[string]host.Host{"h": {Policy: policy.Policy{Exec: true}}}), tr), nil)
	st, ct := sdk.NewInMemoryTransports()
	ss, err := server.Connect(ctx, st, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer ss.Close()
	cs, err := sdk.NewClient(&sdk.Implementation{Name: "argv-test", Version: "1"}, nil).Connect(ctx, ct, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer cs.Close()
	res, err := cs.CallTool(ctx, &sdk.CallToolParams{Name: "ash_exec", Arguments: map[string]any{"host": "h", "argv": []any{"ls", "-la"}}})
	if err != nil || res.IsError {
		t.Fatalf("%+v %v", res, err)
	}
	if len(tr.argv) != 2 || tr.argv[0] != "ls" || tr.argv[1] != "-la" {
		t.Fatalf("%v", tr.argv)
	}
}

func TestDecodeContentTextAndBinary(t *testing.T) {
	text := "hi"
	if data, err := decodeContent(&text, nil); err != nil || string(data) != "hi" {
		t.Fatalf("%q %v", data, err)
	}
	binary := base64.StdEncoding.EncodeToString([]byte{0xff, 0x00})
	if data, err := decodeContent(nil, &binary); err != nil || len(data) != 2 || data[0] != 0xff {
		t.Fatalf("%v %v", data, err)
	}
	if _, err := decodeContent(&text, &binary); err == nil {
		t.Fatal("accepted both content fields")
	}
	bad := "!!!"
	if _, err := decodeContent(nil, &bad); err == nil {
		t.Fatal("accepted invalid base64")
	}
	if data, err := decodeContent(nil, nil); err != nil || data != nil {
		t.Fatalf("%v %v", data, err)
	}
}

func TestExecStdinFields(t *testing.T) {
	text := "a\x00b"
	if data, set, err := execStdin(execInput{Stdin: &text}); err != nil || !set || string(data) != text {
		t.Fatalf("%q %v %v", data, set, err)
	}
	binary := base64.StdEncoding.EncodeToString([]byte{0xff, 0x00})
	if data, set, err := execStdin(execInput{StdinB64: &binary}); err != nil || !set || len(data) != 2 || data[0] != 0xff {
		t.Fatalf("%v %v %v", data, set, err)
	}
	if _, _, err := execStdin(execInput{Stdin: &text, StdinB64: &binary}); err == nil {
		t.Fatal("accepted both stdin fields")
	}
	bad := "!!!"
	if _, _, err := execStdin(execInput{StdinB64: &bad}); err == nil {
		t.Fatal("accepted invalid base64")
	}
	if data, set, err := execStdin(execInput{}); err != nil || set || data != nil {
		t.Fatalf("%v %v %v", data, set, err)
	}
}

func TestClientCancellationReachesService(t *testing.T) {
	ctx, cancelAll := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancelAll()
	tr := &cancelTransport{started: make(chan struct{}), canceled: make(chan struct{})}
	server := New(service.New(host.New(map[string]host.Host{"h": {Policy: policy.Policy{Exec: true}}}), tr), nil)
	st, ct := sdk.NewInMemoryTransports()
	ss, err := server.Connect(ctx, st, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer ss.Close()
	cs, err := sdk.NewClient(&sdk.Implementation{Name: "test", Version: "1"}, nil).Connect(ctx, ct, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer cs.Close()
	callCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	done := make(chan struct{})
	go func() {
		defer close(done)
		cs.CallTool(callCtx, &sdk.CallToolParams{Name: "ash_exec", Arguments: map[string]any{"host": "h", "command": "sleep 10"}})
	}()
	select {
	case <-tr.started:
	case <-ctx.Done():
		t.Fatal("tool did not start")
	}
	cancel()
	select {
	case <-tr.canceled:
	case <-ctx.Done():
		t.Fatal("cancellation did not reach transport")
	}
	<-done
}

type persistentBackend struct {
	shell.Backend
	id, input, cursor string
}

func (b *persistentBackend) Name() string { return "test" }
func (b *persistentBackend) Create(_ context.Context, _ host.Host, id, cwd string) error {
	b.id = id
	return nil
}
func (b *persistentBackend) List(context.Context, host.Host) ([]string, error) {
	if b.id == "" {
		return []string{}, nil
	}
	return []string{b.id}, nil
}
func (b *persistentBackend) Send(_ context.Context, _ host.Host, id, input string) error {
	b.input = input
	return nil
}
func (b *persistentBackend) Read(_ context.Context, _ host.Host, _ string, req shell.ReadRequest) (shell.Output, error) {
	b.cursor = req.Cursor
	return shell.Output{Content: b.input, Cursor: "next"}, nil
}
func (b *persistentBackend) Close(context.Context, host.Host, string) error { b.id = ""; return nil }

func TestPersistentShellTools(t *testing.T) {
	ctx := context.Background()
	backend := new(persistentBackend)
	hosts := host.New(map[string]host.Host{"h": {Policy: policy.Policy{Exec: true}}, "denied": {}})
	server := New(service.New(hosts, nil), service.NewShells(hosts, backend))
	st, ct := sdk.NewInMemoryTransports()
	ss, err := server.Connect(ctx, st, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer ss.Close()
	cs, err := sdk.NewClient(&sdk.Implementation{Name: "shell-test", Version: "1"}, nil).Connect(ctx, ct, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer cs.Close()
	call := func(name string, args map[string]any) map[string]any {
		t.Helper()
		result, err := cs.CallTool(ctx, &sdk.CallToolParams{Name: name, Arguments: args})
		if err != nil {
			t.Fatal(err)
		}
		if result.IsError {
			t.Fatal(result.GetError())
		}
		data, err := json.Marshal(result.StructuredContent)
		if err != nil {
			t.Fatal(err)
		}
		var obj map[string]any
		if err = json.Unmarshal(data, &obj); err != nil {
			t.Fatal(err)
		}
		return obj
	}
	created := call("ash_shell_create", map[string]any{"host": "h", "cwd": "/tmp"})
	id := created["id"]
	if id != backend.id || created["backend"] != "test" {
		t.Fatal(created)
	}
	list := call("ash_shell_list", map[string]any{"host": "h"})
	if len(list["shells"].([]any)) != 1 {
		t.Fatal(list)
	}
	sent := call("ash_shell_send", map[string]any{"host": "h", "shell_id": id, "input": "pwd\n"})
	if sent["sent"] != true || sent["cursor"] != "next" {
		t.Fatal(sent)
	}
	output := call("ash_shell_read", map[string]any{"host": "h", "shell_id": id})
	if output["content"] != "pwd\n" || output["truncated"] != false {
		t.Fatal(output)
	}
	waited := call("ash_shell_wait", map[string]any{"host": "h", "shell_id": id, "until": "pwd", "timeout_ms": 1000})
	if waited["matched"] != true || waited["content"] != "pwd\n" {
		t.Fatal(waited)
	}
	call("ash_shell_close", map[string]any{"host": "h", "shell_id": id})
	list = call("ash_shell_list", map[string]any{"host": "h"})
	if len(list["shells"].([]any)) != 0 {
		t.Fatal(list)
	}
	denied, err := cs.CallTool(ctx, &sdk.CallToolParams{Name: "ash_shell_create", Arguments: map[string]any{"host": "denied"}})
	if err != nil || !denied.IsError {
		t.Fatalf("%v %v", denied, err)
	}
}

type rangeReadTransport struct{ transport.Transport }

func (rangeReadTransport) ReadRange(_ context.Context, _ host.Host, _ string, offset, limit int64) (transport.FileRange, error) {
	return transport.FileRange{Data: []byte("tail\n"), Offset: 95, Size: 100}, nil
}

func TestReadToolRange(t *testing.T) {
	ctx := context.Background()
	server := New(service.New(host.New(map[string]host.Host{"h": {Policy: policy.Policy{Read: true}}}), rangeReadTransport{}), nil)
	st, ct := sdk.NewInMemoryTransports()
	ss, err := server.Connect(ctx, st, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer ss.Close()
	cs, err := sdk.NewClient(&sdk.Implementation{Name: "test", Version: "1"}, nil).Connect(ctx, ct, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer cs.Close()
	res, err := cs.CallTool(ctx, &sdk.CallToolParams{Name: "ash_read", Arguments: map[string]any{"host": "h", "path": "/log", "offset": -5}})
	if err != nil || res.IsError {
		t.Fatalf("%+v %v", res, err)
	}
	data, _ := json.Marshal(res.StructuredContent)
	var out struct {
		Content  string `json:"content"`
		Size     int    `json:"size"`
		Offset   *int64 `json:"offset"`
		FileSize *int64 `json:"file_size"`
	}
	if err := json.Unmarshal(data, &out); err != nil || out.Content != "tail\n" || out.Size != 5 || out.Offset == nil || *out.Offset != 95 || out.FileSize == nil || *out.FileSize != 100 {
		t.Fatalf("%s %v", data, err)
	}
}
