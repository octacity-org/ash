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
	ash [--config PATH] exec HOST [--stdin] [--cwd PATH] [--env KEY=VALUE] [--timeout 30s] -- COMMAND...
	ash [--config PATH] execv HOST [--stdin] [--cwd PATH] [--env KEY=VALUE] [--timeout 30s] -- PROGRAM ARG...
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
		var req transport.ExecRequest
		var err error
		if args[0] == "execv" {
			req, err = parseExecv(args[1:])
		} else {
			req, err = parseExec(args[1:])
		}
		if err != nil {
			return fail(err)
		}
		if req.StdinSet {
			data, err := readInput(ctx, in, transport.MaxExecInputSize)
			if err != nil {
				return fail(err)
			}
			req.Stdin = data
		}
		r, err := s.Exec(ctx, req)
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
		if r.ExitCode < 0 || r.ExitCode > 255 {
			return 1
		}
		return r.ExitCode
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

func parseExecv(args []string) (transport.ExecRequest, error) {
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

func parseExec(args []string) (transport.ExecRequest, error) {
	var req transport.ExecRequest
	if len(args) == 0 {
		return req, fmt.Errorf("exec requires HOST [flags] -- COMMAND")
	}
	req.Host = args[0]
	req.Env = make(map[string]string)
	return parseExecFlags(args, "exec")
}

// parseExecFlags parses the option list shared by exec and execv. Shell code is
// stored in Command; structured arguments are stored in Argv.
func parseExecFlags(args []string, verb string) (transport.ExecRequest, error) {
	var req transport.ExecRequest
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
