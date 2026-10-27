// Package cli provides the command-line adapter for ASH services.
package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"time"

	"ash/internal/service"
	"ash/internal/transport"
)

const Usage = `Usage:
  ash --version
  ash [--config PATH] hosts
	ash [--config PATH] host add NAME (--address ADDRESS --user USER [--port N] [--identity PATH] | --ssh-alias ALIAS) [--shell-backend zellij|tmux] [--exec] [--read] [--write]
	ash [--config PATH] doctor [HOST] [--json]
	ash [--config PATH] exec HOST [--stdin|--stream] [--cwd PATH] [--env KEY=VALUE] [--timeout 30s] -- COMMAND...
	ash [--config PATH] execv HOST [--stdin|--stream] [--cwd PATH] [--env KEY=VALUE] [--timeout 30s] -- PROGRAM ARG...
  ash [--config PATH] rsh [-l USER] HOST COMMAND...
  ash [--config PATH] read HOST PATH [--offset N] [--limit N]
  ash [--config PATH] write HOST PATH [--atomic] < FILE
  ash [--config PATH] stat HOST PATH
  ash [--config PATH] list HOST PATH
  ash [--config PATH] mkdir HOST PATH
  ash [--config PATH] rename HOST FROM TO
  ash [--config PATH] remove HOST PATH
  ash [--config PATH] download HOST REMOTE_DIR LOCAL_DIR
  ash [--config PATH] upload HOST LOCAL_DIR REMOTE_DIR
  ash [--config PATH] shell create HOST [--cwd PATH]
  ash [--config PATH] shell list HOST
  ash [--config PATH] shell send HOST ID [INPUT]
  ash [--config PATH] shell read HOST ID [--cursor VALUE] [--json]
  ash [--config PATH] shell wait HOST ID [--cursor VALUE] [--until TEXT|--regex EXPR] [--timeout 30s] [--json]
  ash [--config PATH] shell close HOST ID
  ash setup [AGENT] [--scope user|project] [--project DIR] [--print]
  ash [--config PATH] mcp

COMMAND is shell code executed through the remote user's shell.
execv runs PROGRAM with structured ARG words and strict quoting; no shell is involved.
Quote remote ~/ paths to prevent your local shell from expanding them.
Read with --offset or --limit returns a slice of any file size; a negative offset counts from the end.
With --stdin, ASH forwards up to 64 KiB from standard input to the command.
With --stream, standard input, output and error flow to and from the command
without size caps, and --timeout limits how long no data may move.
rsh streams like exec --stream with the calling convention of rsync -e.
Shell send reads stdin if INPUT is omitted. Include a newline to execute input.
Shell read returns a terminal snapshot; pass --cursor from a previous --json read for output added since then.
Shell wait blocks for new output or --until/--regex and never closes the shell on timeout.
`

func Run(ctx context.Context, args []string, s *service.Service, shells *service.ShellService, in io.Reader, out, errout io.Writer) int {
	fail := func(err error) int { fmt.Fprintln(errout, "ash:", err); return 1 }
	if len(args) == 0 || args[0] == "--help" || args[0] == "-h" {
		fmt.Fprint(out, Usage)
		return 0
	}
	switch args[0] {
	case "shell":
		if err := runShell(ctx, args[1:], shells, in, out, errout); err != nil {
			return fail(err)
		}
		return 0
	case "hosts":
		if len(args) != 1 {
			return fail(fmt.Errorf("hosts takes no arguments"))
		}
		if err := json.NewEncoder(out).Encode(s.Hosts()); err != nil {
			return fail(err)
		}
		return 0
	case "exec", "execv":
		var req execArgs
		var err error
		if args[0] == "execv" {
			req, err = parseExecv(args[1:])
		} else {
			req, err = parseExec(args[1:])
		}
		if err != nil {
			return fail(err)
		}
		if req.stream {
			if req.StdinSet {
				return fail(fmt.Errorf("--stdin and --stream are mutually exclusive; --stream always forwards stdin"))
			}
			return runStream(ctx, s, req.ExecRequest, in, out, errout)
		}
		if req.StdinSet {
			data, err := readInput(ctx, in, transport.MaxExecInputSize)
			if err != nil {
				return fail(err)
			}
			req.Stdin = data
		}
		r, err := s.Exec(ctx, req.ExecRequest)
		if err != nil {
			return fail(err)
		}
		if _, err := io.WriteString(out, r.Stdout); err != nil {
			return fail(err)
		}
		if _, err := io.WriteString(errout, r.Stderr); err != nil {
			return fail(err)
		}
		if r.StdoutTruncated {
			fmt.Fprintln(errout, "\nash: stdout truncated at 8 MiB")
		}
		if r.StderrTruncated {
			fmt.Fprintln(errout, "\nash: stderr truncated at 8 MiB")
		}
		return exitStatus(r.ExitCode)
	case "rsh":
		req, err := parseRsh(args[1:], s)
		if err != nil {
			return fail(err)
		}
		return runStream(ctx, s, req, in, out, errout)
	case "read":
		if err := runRead(ctx, args[1:], s, out); err != nil {
			return fail(err)
		}
		return 0
	case "stat":
		if len(args) != 3 {
			return fail(fmt.Errorf("stat requires HOST PATH"))
		}
		info, err := s.Stat(ctx, args[1], args[2])
		if err != nil {
			return fail(err)
		}
		if err := json.NewEncoder(out).Encode(info); err != nil {
			return fail(err)
		}
		return 0
	case "write":
		if err := runWrite(ctx, args[1:], s, in); err != nil {
			return fail(err)
		}
		return 0
	case "list":
		if len(args) != 3 {
			return fail(fmt.Errorf("list requires HOST PATH"))
		}
		entries, err := s.List(ctx, args[1], args[2])
		if err != nil {
			return fail(err)
		}
		if err := json.NewEncoder(out).Encode(entries); err != nil {
			return fail(err)
		}
		return 0
	case "mkdir", "remove":
		if len(args) != 3 {
			return fail(fmt.Errorf("%s requires HOST PATH", args[0]))
		}
		var opErr error
		if args[0] == "mkdir" {
			opErr = s.Mkdir(ctx, args[1], args[2])
		} else {
			opErr = s.Remove(ctx, args[1], args[2])
		}
		if opErr != nil {
			return fail(opErr)
		}
		return encodeOK(out, fail)
	case "rename":
		if len(args) != 4 {
			return fail(fmt.Errorf("rename requires HOST FROM TO"))
		}
		if err := s.Rename(ctx, args[1], args[2], args[3]); err != nil {
			return fail(err)
		}
		return encodeOK(out, fail)
	case "download":
		if err := runDownload(ctx, args[1:], s); err != nil {
			return fail(err)
		}
		return 0
	case "upload":
		if err := runUpload(ctx, args[1:], s); err != nil {
			return fail(err)
		}
		return 0
	default:
		return fail(fmt.Errorf("unknown command %q", args[0]))
	}
}

// exitStatus maps a remote exit code to a process exit status.
func exitStatus(code int) int {
	if code < 0 || code > 255 {
		return 1
	}
	return code
}

// runStream connects local stdio to a remote command and returns its exit
// status.
func runStream(ctx context.Context, s *service.Service, req transport.ExecRequest, in io.Reader, out, errout io.Writer) int {
	r, err := s.ExecStream(ctx, req, transport.Stdio{Stdin: in, Stdout: out, Stderr: errout})
	if err != nil {
		fmt.Fprintln(errout, "ash:", err)
		return 1
	}
	return exitStatus(r.ExitCode)
}

// parseRsh accepts the rsh calling convention that rsync -e uses:
// [-l USER] HOST COMMAND... Like ssh, it joins the command words with spaces
// for the remote shell. -l must name the host's configured user, because ASH
// connects only as that user.
func parseRsh(args []string, s *service.Service) (transport.ExecRequest, error) {
	user := ""
	if len(args) >= 2 && args[0] == "-l" {
		user, args = args[1], args[2:]
	}
	if len(args) < 2 {
		return transport.ExecRequest{}, fmt.Errorf("rsh requires [-l USER] HOST COMMAND...")
	}
	req := transport.ExecRequest{Host: args[0], Command: strings.Join(args[1:], " ")}
	if user != "" {
		for _, h := range s.Hosts() {
			if h.Name == req.Host && h.User != user {
				return req, fmt.Errorf("host %q connects as %q, not %q", req.Host, h.User, user)
			}
		}
	}
	return req, nil
}

// execArgs is a parsed exec or execv command line.
type execArgs struct {
	transport.ExecRequest
	stream bool
}

func parseExecv(args []string) (execArgs, error) {
	req, err := parseExecFlags(args, "execv")
	if err != nil {
		return req, err
	}
	if len(req.Argv) == 0 {
		return req, fmt.Errorf("execv requires -- before PROGRAM")
	}
	// Reject the shell form of the same request.
	req.Command = ""
	return req, nil
}

func parseExec(args []string) (execArgs, error) {
	var req execArgs
	if len(args) == 0 {
		return req, fmt.Errorf("exec requires HOST [flags] -- COMMAND")
	}
	req.Host = args[0]
	req.Env = make(map[string]string)
	return parseExecFlags(args, "exec")
}

// parseExecFlags parses the option list shared by exec and execv. Shell code is
// stored in Command; structured arguments are stored in Argv.
func parseExecFlags(args []string, verb string) (execArgs, error) {
	var req execArgs
	if len(args) == 0 {
		return req, fmt.Errorf("%s requires HOST [flags] -- COMMAND", verb)
	}
	req.Host = args[0]
	req.Env = make(map[string]string)
	for i := 1; i < len(args); i++ {
		if args[i] == "--" {
			if i+1 == len(args) {
				return req, fmt.Errorf("command must not be empty")
			}
			if verb == "execv" {
				req.Argv = append([]string(nil), args[i+1:]...)
			} else {
				req.Command = strings.Join(args[i+1:], " ")
			}
			return req, nil
		}
		if args[i] == "--stdin" {
			req.StdinSet = true
			continue
		}
		if args[i] == "--stream" {
			req.stream = true
			continue
		}
		key, value, hasValue := strings.Cut(args[i], "=")
		if key != "--cwd" && key != "--env" && key != "--timeout" {
			return req, fmt.Errorf("unknown exec option %q; put command after --", key)
		}
		if !hasValue {
			i++
			if i == len(args) {
				return req, fmt.Errorf("%s requires a value", key)
			}
			value = args[i]
		}
		switch key {
		case "--cwd":
			req.Cwd = value
		case "--env":
			name, v, ok := strings.Cut(value, "=")
			if !ok || name == "" {
				return req, fmt.Errorf("--env requires KEY=VALUE")
			}
			req.Env[name] = v
		case "--timeout":
			d, err := time.ParseDuration(value)
			if err != nil || d <= 0 {
				return req, fmt.Errorf("--timeout requires a positive duration")
			}
			req.Timeout = d
		}
	}
	return req, fmt.Errorf("%s requires -- before command", verb)
}
