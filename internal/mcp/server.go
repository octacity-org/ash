// Package mcp adapts the shared services to the MCP stdio protocol.
package mcp

import (
	"context"
	"encoding/base64"
	"fmt"

	sdk "github.com/modelcontextprotocol/go-sdk/mcp"

	"ash/internal/service"
	"ash/internal/transport"
)

// Version is overridden by the release build and reported by both CLI and MCP.
var Version = "dev"

type hostsResult struct {
	Hosts []service.HostInfo `json:"hosts"`
}
type execInput struct {
	Host      string            `json:"host"`
	Command   string            `json:"command,omitempty" jsonschema:"Shell code executed through the remote user's shell. Mutually exclusive with argv."`
	Argv      []string          `json:"argv,omitempty" jsonschema:"Structured program and arguments. Executed without a shell, so executable restrictions are enforceable. Mutually exclusive with command."`
	Cwd       string            `json:"cwd,omitempty"`
	Env       map[string]string `json:"env,omitempty"`
	TimeoutMS int64             `json:"timeout_ms,omitempty"`
	Stdin     *string           `json:"stdin,omitempty" jsonschema:"UTF-8 text forwarded to the remote process stdin, at most 64 KiB. Set it to an empty string to send empty input."`
	StdinB64  *string           `json:"stdin_base64,omitempty" jsonschema:"Base64-encoded binary forwarded to the remote process stdin, at most 64 KiB. Mutually exclusive with stdin."`
}
type execOutput struct {
	ExitCode        int    `json:"exit_code"`
	Stdout          string `json:"stdout"`
	Stderr          string `json:"stderr"`
	StdoutTruncated bool   `json:"stdout_truncated"`
	StderrTruncated bool   `json:"stderr_truncated"`
	DurationMS      int64  `json:"duration_ms"`
}
type fileInput struct {
	Host string `json:"host"`
	Path string `json:"path"`
}
type readInput struct {
	Host     string `json:"host"`
	Path     string `json:"path"`
	Encoding string `json:"encoding,omitempty" jsonschema:"Optional. \"text\" (default) returns UTF-8 content; \"base64\" returns base64 for binary files."`
	Offset   int64  `json:"offset,omitempty" jsonschema:"Optional byte offset to start reading at. Negative values count back from the end of the file, for example -65536 to tail a log."`
	Limit    int64  `json:"limit,omitempty" jsonschema:"Optional maximum bytes to read, at most 4194304. Setting offset or limit reads a slice, which works on files of any size."`
}
type writeInput struct {
	Host          string  `json:"host"`
	Path          string  `json:"path"`
	Content       *string `json:"content,omitempty"`
	ContentBase64 *string `json:"content_base64,omitempty" jsonschema:"Base64-encoded bytes. Mutually exclusive with content."`
}
type readOutput struct {
	Content       string `json:"content,omitempty"`
	ContentBase64 string `json:"content_base64,omitempty"`
	Size          int    `json:"size"`
	// Offset and FileSize are set for slice reads so the caller can page.
	Offset   *int64 `json:"offset,omitempty"`
	FileSize *int64 `json:"file_size,omitempty"`
}
type writeOutput struct {
	Size int `json:"size"`
}
type renameInput struct {
	Host string `json:"host"`
	From string `json:"from"`
	To   string `json:"to"`
}
type listOutput struct {
	Entries []transport.DirEntry `json:"entries"`
}
type treeResultEntry struct {
	Path          string `json:"path"`
	IsDir         bool   `json:"is_dir"`
	Mode          string `json:"mode,omitempty"`
	Size          int    `json:"size"`
	ContentBase64 string `json:"content_base64,omitempty"`
}
type downloadOutput struct {
	Entries []treeResultEntry `json:"entries"`
}
type treeInputEntry struct {
	Path          string `json:"path"`
	IsDir         bool   `json:"is_dir"`
	ContentBase64 string `json:"content_base64,omitempty"`
}
type uploadInput struct {
	Host    string           `json:"host"`
	Path    string           `json:"path"`
	Entries []treeInputEntry `json:"entries"`
}
type okOutput struct {
	OK bool `json:"ok"`
}

// decodeContent resolves the mutually exclusive text and base64 payload fields.
func decodeContent(content *string, contentBase64 *string) ([]byte, error) {
	if content != nil && contentBase64 != nil {
		return nil, fmt.Errorf("provide only one of content or content_base64")
	}
	if contentBase64 != nil {
		data, err := base64.StdEncoding.DecodeString(*contentBase64)
		if err != nil {
			return nil, fmt.Errorf("content_base64 is not valid base64: %w", err)
		}
		return data, nil
	}
	if content != nil {
		return []byte(*content), nil
	}
	return nil, nil
}

// execStdin resolves the mutually exclusive text and binary stdin fields.
func execStdin(in execInput) ([]byte, bool, error) {
	if in.Stdin != nil && in.StdinB64 != nil {
		return nil, false, fmt.Errorf("provide only one of stdin or stdin_base64")
	}
	if in.Stdin != nil {
		return []byte(*in.Stdin), true, nil
	}
	if in.StdinB64 != nil {
		data, err := base64.StdEncoding.DecodeString(*in.StdinB64)
		if err != nil {
			return nil, false, fmt.Errorf("stdin_base64 is not valid base64: %w", err)
		}
		return data, true, nil
	}
	return nil, false, nil
}

func New(s *service.Service, shells *service.ShellService) *sdk.Server {
	server := sdk.NewServer(&sdk.Implementation{Name: "ash", Version: Version}, nil)
	sdk.AddTool(server, &sdk.Tool{Name: "ash_hosts", Description: "List configured hosts, granted capabilities, and policy limits (path roots, allowed commands, bounds, shell backend)."}, func(ctx context.Context, _ *sdk.CallToolRequest, _ struct{}) (*sdk.CallToolResult, hostsResult, error) {
		return nil, hostsResult{Hosts: s.Hosts()}, nil
	})
	sdk.AddTool(server, &sdk.Tool{Name: "ash_exec", Description: "Execute shell code on a configured host. Non-zero process exits are results, not tool errors."}, func(ctx context.Context, _ *sdk.CallToolRequest, in execInput) (*sdk.CallToolResult, execOutput, error) {
		timeout, err := service.TimeoutMillis(in.TimeoutMS)
		if err != nil {
			return nil, execOutput{}, err
		}
		stdin, stdinSet, err := execStdin(in)
		if err != nil {
			return nil, execOutput{}, err
		}
		r, err := s.Exec(ctx, transport.ExecRequest{Host: in.Host, Command: in.Command, Argv: in.Argv, Cwd: in.Cwd, Env: in.Env, Timeout: timeout, Stdin: stdin, StdinSet: stdinSet})
		return nil, execOutput{ExitCode: r.ExitCode, Stdout: r.Stdout, Stderr: r.Stderr, StdoutTruncated: r.StdoutTruncated, StderrTruncated: r.StderrTruncated, DurationMS: r.Duration.Milliseconds()}, err
	})
	sdk.AddTool(server, &sdk.Tool{Name: "ash_read", Description: "Read a file using SFTP: the whole file up to 4 MiB, or a slice of any file with offset/limit (negative offset tails). Returns UTF-8 content by default, or base64 when encoding is \"base64\". Text slices drop partial characters at their edges; offset reports where the content starts."}, func(ctx context.Context, _ *sdk.CallToolRequest, in readInput) (*sdk.CallToolResult, readOutput, error) {
		if in.Encoding != "" && in.Encoding != "text" && in.Encoding != "base64" {
			return nil, readOutput{}, fmt.Errorf("encoding must be \"text\" or \"base64\"")
		}
		if in.Offset == 0 && in.Limit == 0 {
			data, err := s.Read(ctx, in.Host, in.Path)
			if err != nil {
				return nil, readOutput{}, err
			}
			out := readOutput{Size: len(data)}
			if in.Encoding == "base64" {
				out.ContentBase64 = base64.StdEncoding.EncodeToString(data)
				return nil, out, nil
			}
			content, err := service.Text(data)
			if err != nil {
				return nil, readOutput{}, err
			}
			out.Content = content
			return nil, out, nil
		}
		r, err := s.ReadRange(ctx, in.Host, in.Path, in.Offset, in.Limit)
		if err != nil {
			return nil, readOutput{}, err
		}
		out := readOutput{Size: len(r.Data), Offset: &r.Offset, FileSize: &r.Size}
		if in.Encoding == "base64" {
			out.ContentBase64 = base64.StdEncoding.EncodeToString(r.Data)
			return nil, out, nil
		}
		content, offset, err := service.TextRange(r)
		if err != nil {
			return nil, readOutput{}, err
		}
		out.Content, out.Size, out.Offset = content, len(content), &offset
		return nil, out, nil
	})
	sdk.AddTool(server, &sdk.Tool{Name: "ash_write", Description: "Create or truncate a file through SFTP, up to 4 MiB. Parent directory must exist. Supplying content_base64 implies binary semantics."}, func(ctx context.Context, _ *sdk.CallToolRequest, in writeInput) (*sdk.CallToolResult, writeOutput, error) {
		data, err := decodeContent(in.Content, in.ContentBase64)
		if err != nil {
			return nil, writeOutput{}, err
		}
		err = s.Write(ctx, in.Host, in.Path, data)
		return nil, writeOutput{Size: len(data)}, err
	})
	sdk.AddTool(server, &sdk.Tool{Name: "ash_stat", Description: "Inspect file metadata through SFTP. Requires read capability."}, func(ctx context.Context, _ *sdk.CallToolRequest, in fileInput) (*sdk.CallToolResult, transport.FileInfo, error) {
		r, err := s.Stat(ctx, in.Host, in.Path)
		return nil, r, err
	})
	sdk.AddTool(server, &sdk.Tool{Name: "ash_list", Description: "List the sorted direct children of a remote directory. Requires read capability."}, func(ctx context.Context, _ *sdk.CallToolRequest, in fileInput) (*sdk.CallToolResult, listOutput, error) {
		entries, err := s.List(ctx, in.Host, in.Path)
		return nil, listOutput{Entries: entries}, err
	})
	sdk.AddTool(server, &sdk.Tool{Name: "ash_mkdir", Description: "Create one remote directory. Parent directories must already exist. Requires write capability."}, func(ctx context.Context, _ *sdk.CallToolRequest, in fileInput) (*sdk.CallToolResult, okOutput, error) {
		err := s.Mkdir(ctx, in.Host, in.Path)
		return nil, okOutput{OK: err == nil}, err
	})
	sdk.AddTool(server, &sdk.Tool{Name: "ash_rename", Description: "Rename or move a remote file or directory. Requires write capability."}, func(ctx context.Context, _ *sdk.CallToolRequest, in renameInput) (*sdk.CallToolResult, okOutput, error) {
		err := s.Rename(ctx, in.Host, in.From, in.To)
		return nil, okOutput{OK: err == nil}, err
	})
	sdk.AddTool(server, &sdk.Tool{Name: "ash_remove", Description: "Remove a remote file or empty directory. Never recursive. Requires write capability."}, func(ctx context.Context, _ *sdk.CallToolRequest, in fileInput) (*sdk.CallToolResult, okOutput, error) {
		err := s.Remove(ctx, in.Host, in.Path)
		return nil, okOutput{OK: err == nil}, err
	})
	sdk.AddTool(server, &sdk.Tool{Name: "ash_write_atomic", Description: "Atomically replace a remote file: a same-directory temporary file is written and renamed, leaving the prior file intact on failure. Requires write capability."}, func(ctx context.Context, _ *sdk.CallToolRequest, in writeInput) (*sdk.CallToolResult, writeOutput, error) {
		data, err := decodeContent(in.Content, in.ContentBase64)
		if err != nil {
			return nil, writeOutput{}, err
		}
		err = s.AtomicWrite(ctx, in.Host, in.Path, data)
		return nil, writeOutput{Size: len(data)}, err
	})
	sdk.AddTool(server, &sdk.Tool{Name: "ash_download", Description: "Return a bounded remote directory tree (max 4 MiB, 1000 entries, depth 32) as base64 file entries. Symlinks are skipped. Requires read capability."}, func(ctx context.Context, _ *sdk.CallToolRequest, in fileInput) (*sdk.CallToolResult, downloadOutput, error) {
		entries, err := s.ReadTree(ctx, in.Host, in.Path)
		if err != nil {
			return nil, downloadOutput{}, err
		}
		out := make([]treeResultEntry, 0, len(entries))
		for _, entry := range entries {
			item := treeResultEntry{Path: entry.Path, IsDir: entry.IsDir, Mode: entry.Mode, Size: len(entry.Data)}
			if !entry.IsDir {
				item.ContentBase64 = base64.StdEncoding.EncodeToString(entry.Data)
			}
			out = append(out, item)
		}
		return nil, downloadOutput{Entries: out}, nil
	})
	sdk.AddTool(server, &sdk.Tool{Name: "ash_upload", Description: "Write a bounded remote directory tree from path/is_dir/content_base64 entries. Rejects absolute paths, traversal, duplicates, and type conflicts before mutating. Requires write capability."}, func(ctx context.Context, _ *sdk.CallToolRequest, in uploadInput) (*sdk.CallToolResult, writeOutput, error) {
		entries := make([]transport.TreeEntry, 0, len(in.Entries))
		total := 0
		for _, entry := range in.Entries {
			out := transport.TreeEntry{Path: entry.Path, IsDir: entry.IsDir}
			if !entry.IsDir {
				data, err := base64.StdEncoding.DecodeString(entry.ContentBase64)
				if err != nil {
					return nil, writeOutput{}, fmt.Errorf("entry %q: content_base64 is not valid base64", entry.Path)
				}
				out.Data = data
				total += len(data)
			}
			entries = append(entries, out)
		}
		err := s.WriteTree(ctx, in.Host, in.Path, entries)
		return nil, writeOutput{Size: total}, err
	})
	registerShellTools(server, shells)
	return server
}
