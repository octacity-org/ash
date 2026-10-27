package cli

import (
	"bytes"
	"context"
	"io"
	"strings"
	"testing"

	"ash/internal/host"
	"ash/internal/policy"
	"ash/internal/service"
	"ash/internal/transport"
)

type streamRecorder struct {
	transport.Transport
	request transport.ExecRequest
	calls   int
}

func (r *streamRecorder) ExecStream(_ context.Context, _ host.Host, req transport.ExecRequest, stdio transport.Stdio) (transport.ExecResult, error) {
	r.calls++
	r.request = req
	if _, err := io.Copy(stdio.Stdout, stdio.Stdin); err != nil {
		return transport.ExecResult{}, err
	}
	io.WriteString(stdio.Stderr, "err")
	return transport.ExecResult{ExitCode: 4}, nil
}

func streamCLI() (*streamRecorder, *service.Service) {
	r := new(streamRecorder)
	return r, service.New(host.New(map[string]host.Host{"h": {User: "deploy", Policy: policy.Policy{Exec: true}}}), r)
}

func TestExecStreamConnectsStdioAndExitCode(t *testing.T) {
	r, s := streamCLI()
	input := strings.Repeat("z", transport.MaxExecInputSize+1)
	var out, errout bytes.Buffer
	code := Run(context.Background(), []string{"execv", "h", "--stream", "--cwd", "/srv", "--", "tar", "x"}, s, nil, strings.NewReader(input), &out, &errout)
	if code != 4 || out.String() != input || errout.String() != "err" {
		t.Fatalf("%d, %d bytes out, %q", code, out.Len(), errout.String())
	}
	if len(r.request.Argv) != 2 || r.request.Argv[0] != "tar" || r.request.Cwd != "/srv" {
		t.Fatalf("%+v", r.request)
	}
	code = Run(context.Background(), []string{"exec", "h", "--stream", "--", "cat", "-"}, s, nil, strings.NewReader("a"), &out, &errout)
	if code != 4 || r.request.Command != "cat -" {
		t.Fatalf("%d %+v", code, r.request)
	}
}

func TestExecStreamRejectsStdinFlag(t *testing.T) {
	r, s := streamCLI()
	var out, errout bytes.Buffer
	code := Run(context.Background(), []string{"exec", "h", "--stdin", "--stream", "--", "cat"}, s, nil, strings.NewReader(""), &out, &errout)
	if code != 1 || r.calls != 0 || !strings.Contains(errout.String(), "mutually exclusive") {
		t.Fatalf("%d %d %q", code, r.calls, errout.String())
	}
}

func TestRshFollowsRsyncConvention(t *testing.T) {
	r, s := streamCLI()
	var out, errout bytes.Buffer
	args := []string{"rsh", "-l", "deploy", "h", "rsync", "--server", "-logDtpre.iLsfxCIvu", ".", "/srv/dest"}
	if code := Run(context.Background(), args, s, nil, strings.NewReader("in"), &out, &errout); code != 4 || out.String() != "in" {
		t.Fatalf("%d %q %q", code, out.String(), errout.String())
	}
	if r.request.Host != "h" || r.request.Command != "rsync --server -logDtpre.iLsfxCIvu . /srv/dest" || len(r.request.Argv) != 0 {
		t.Fatalf("%+v", r.request)
	}
	if code := Run(context.Background(), []string{"rsh", "h", "true"}, s, nil, strings.NewReader(""), &out, &errout); code != 4 || r.request.Command != "true" {
		t.Fatalf("without -l: %d %+v", code, r.request)
	}
}

func TestRshRejectsOtherUserAndMissingCommand(t *testing.T) {
	r, s := streamCLI()
	for _, args := range [][]string{{"rsh", "-l", "root", "h", "true"}, {"rsh", "h"}, {"rsh", "-l", "deploy", "h"}} {
		var out, errout bytes.Buffer
		if code := Run(context.Background(), args, s, nil, strings.NewReader(""), &out, &errout); code != 1 {
			t.Fatalf("%v: exit %d", args, code)
		}
	}
	if r.calls != 0 {
		t.Fatalf("refused rsh reached transport %d times", r.calls)
	}
}

func TestForwardRejectsBadArguments(t *testing.T) {
	s := service.New(host.New(map[string]host.Host{"h": {Policy: policy.Policy{Exec: true}}}), new(streamRecorder))
	for _, args := range [][]string{
		{"forward", "h"},
		{"forward", "h", "8080"},
		{"forward", "h", "x:localhost:3000"},
		{"forward", "h", "70000:localhost:3000"},
		{"forward", "h", "8080:localhost"},
		{"forward", "h", "8080:localhost:3000"}, // forward capability is off
	} {
		var out, errout bytes.Buffer
		if code := Run(context.Background(), args, s, nil, strings.NewReader(""), &out, &errout); code != 1 || errout.Len() == 0 {
			t.Fatalf("%v: exit %d %q", args, code, errout.String())
		}
	}
}
