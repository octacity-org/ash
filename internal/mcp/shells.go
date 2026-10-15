package mcp

import (
	"context"

	"ash/internal/service"
	"ash/internal/shell"
	sdk "github.com/modelcontextprotocol/go-sdk/mcp"
)

type shellCreateInput struct {
	Host string `json:"host"`
	Cwd  string `json:"cwd,omitempty"`
}
type shellHostInput struct {
	Host string `json:"host"`
}
type shellInput struct {
	Host    string `json:"host"`
	ShellID string `json:"shell_id"`
	Cursor  string `json:"cursor,omitempty" jsonschema:"Opaque cursor from a previous read. When set, only output added since that read is returned."`
}
type shellSendInput struct {
	Host    string `json:"host"`
	ShellID string `json:"shell_id"`
	Input   string `json:"input" jsonschema:"Literal terminal input; include a newline to execute a command. No newline is added automatically."`
}
type shellWaitInput struct {
	Host      string `json:"host"`
	ShellID   string `json:"shell_id"`
	Cursor    string `json:"cursor,omitempty" jsonschema:"Opaque cursor from a previous read or wait. Only output after it is considered."`
	Until     string `json:"until,omitempty" jsonschema:"Optional literal to wait for. Mutually exclusive with regex."`
	Regex     string `json:"regex,omitempty" jsonschema:"Optional regular expression to wait for. Mutually exclusive with until."`
	TimeoutMS int64  `json:"timeout_ms" jsonschema:"Required positive timeout in milliseconds, at most 300000."`
}

type shellListOutput struct {
	Shells []shell.Info `json:"shells"`
}
type shellSendOutput struct {
	Sent bool `json:"sent"`
	// Cursor is captured just before delivery; waiting from it observes only
	// output produced after the input was sent.
	Cursor string `json:"cursor,omitempty"`
}
type shellCloseOutput struct {
	Closed bool `json:"closed"`
}

func registerShellTools(server *sdk.Server, s *service.ShellService) {
	sdk.AddTool(server, &sdk.Tool{Name: "ash_shell_create", Description: "Create a persistent shell on a host. Requires exec capability. The shell survives ASH/SSH disconnects."}, func(ctx context.Context, _ *sdk.CallToolRequest, in shellCreateInput) (*sdk.CallToolResult, shell.Info, error) {
		info, err := s.Create(ctx, in.Host, in.Cwd)
		return nil, info, err
	})
	sdk.AddTool(server, &sdk.Tool{Name: "ash_shell_list", Description: "List live ASH-owned shells on a host, querying the remote backend. Requires exec capability."}, func(ctx context.Context, _ *sdk.CallToolRequest, in shellHostInput) (*sdk.CallToolResult, shellListOutput, error) {
		shells, err := s.List(ctx, in.Host)
		return nil, shellListOutput{Shells: shells}, err
	})
	sdk.AddTool(server, &sdk.Tool{Name: "ash_shell_send", Description: "Send literal UTF-8 input to a persistent shell, at most 64 KiB. Include a newline to execute it. Requires exec capability; returns after delivery, not command completion. Returns a cursor captured just before delivery: pass it to ash_shell_wait to observe only the output this input produced."}, func(ctx context.Context, _ *sdk.CallToolRequest, in shellSendInput) (*sdk.CallToolResult, shellSendOutput, error) {
		cursor, err := s.SendWithCursor(ctx, in.Host, in.ShellID, in.Input)
		return nil, shellSendOutput{Sent: err == nil, Cursor: cursor}, err
	})
	sdk.AddTool(server, &sdk.Tool{Name: "ash_shell_read", Description: "Read shell terminal output. Without cursor, returns a bounded snapshot of output and available scrollback. With cursor, returns only output added since that read, or a full snapshot with resync=true. Includes merged stdout/stderr. Requires exec capability."}, func(ctx context.Context, _ *sdk.CallToolRequest, in shellInput) (*sdk.CallToolResult, shell.Output, error) {
		output, err := s.Read(ctx, in.Host, in.ShellID, in.Cursor)
		return nil, output, err
	})
	sdk.AddTool(server, &sdk.Tool{Name: "ash_shell_wait", Description: "Wait for new shell output, or for a literal (until) or regular expression (regex) to appear, with a strict timeout. Does not close the shell on timeout. Requires exec capability. This observes terminal output, not command completion or exit status."}, func(ctx context.Context, _ *sdk.CallToolRequest, in shellWaitInput) (*sdk.CallToolResult, shell.WaitResult, error) {
		timeout, err := service.TimeoutMillis(in.TimeoutMS)
		if err != nil {
			return nil, shell.WaitResult{}, err
		}
		result, err := s.Wait(ctx, in.Host, in.ShellID, shell.WaitRequest{Cursor: in.Cursor, Literal: in.Until, Regex: in.Regex, Timeout: timeout})
		return nil, result, err
	})
	sdk.AddTool(server, &sdk.Tool{Name: "ash_shell_close", Description: "Close one ASH-owned persistent shell and clean up its backend session. Requires exec capability."}, func(ctx context.Context, _ *sdk.CallToolRequest, in shellInput) (*sdk.CallToolResult, shellCloseOutput, error) {
		err := s.Close(ctx, in.Host, in.ShellID)
		return nil, shellCloseOutput{Closed: err == nil}, err
	})
}
