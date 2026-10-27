// Package transport defines remote operation contracts shared by all adapters.
package transport

import (
	"ash/internal/host"
	"context"
	"errors"
	"os"
	"time"
)

const (
	MaxReadSize        = 4 << 20
	MaxWriteSize       = 4 << 20
	MaxOutputSize      = 8 << 20
	MaxExecInputSize   = 64 << 10
	DefaultExecTimeout = 5 * time.Minute
	DefaultFileTimeout = 30 * time.Second

	// Recursive tree operations are bounded by total payload, entry count, and
	// path depth. Removal is never recursive; callers must enumerate trees.
	MaxTreePayload = 4 << 20
	MaxTreeEntries = 1000
	MaxTreeDepth   = 32
)

var (
	ErrAuthentication = errors.New("authentication failed")
	ErrHostKey        = errors.New("host key verification failed")
	ErrTimeout        = errors.New("operation timed out")
	ErrTooLarge       = errors.New("file exceeds size limit")
	ErrInputTooLarge  = errors.New("input exceeds size limit")
)

type ExecRequest struct {
	Host, Command, Cwd string
	Env                map[string]string
	Timeout            time.Duration
	// Argv, when non-empty, is executed as structured program arguments with
	// strict POSIX quoting instead of shell code. Command and Argv are
	// mutually exclusive.
	Argv []string
	// MaxOutput caps each captured stream when smaller than MaxOutputSize.
	MaxOutput int
	// Stdin is bounded binary input forwarded to the remote process. StdinSet
	// distinguishes an explicit empty input from no input at all.
	Stdin    []byte
	StdinSet bool
}
type ExecResult struct {
	ExitCode                         int
	Stdout, Stderr                   string
	StdoutTruncated, StderrTruncated bool
	Duration                         time.Duration
}
type FileInfo struct {
	Path    string    `json:"path"`
	Size    int64     `json:"size"`
	Mode    string    `json:"mode"`
	ModTime time.Time `json:"modified_at"`
	IsDir   bool      `json:"is_dir"`
}

// DirEntry is one direct child returned by List.
type DirEntry struct {
	Name    string    `json:"name"`
	Path    string    `json:"path"`
	Size    int64     `json:"size"`
	Mode    string    `json:"mode"`
	ModTime time.Time `json:"modified_at"`
	IsDir   bool      `json:"is_dir"`
	Symlink bool      `json:"symlink"`
}

// TreeEntry is one node of a relative, slash-separated tree. Data carries file
// bytes for reads and writes; directories carry no data.
type TreeEntry struct {
	Path  string `json:"path"`
	Mode  string `json:"mode,omitempty"`
	IsDir bool   `json:"is_dir"`
	Data  []byte `json:"data,omitempty"`
	// Perm holds a file's permission bits (within 0777) to apply when the
	// entry is written; zero means the 0644 default.
	Perm os.FileMode `json:"-"`
}

// FileRange is a bounded slice of a remote file. Offset is the absolute
// position of Data and Size is the file's total size.
type FileRange struct {
	Data   []byte
	Offset int64
	Size   int64
}

type Transport interface {
	Exec(context.Context, host.Host, ExecRequest) (ExecResult, error)
	Read(context.Context, host.Host, string) ([]byte, error)
	// ReadRange reads at most limit bytes starting at offset; a negative
	// offset counts back from the end of the file.
	ReadRange(ctx context.Context, h host.Host, p string, offset, limit int64) (FileRange, error)
	Write(context.Context, host.Host, string, []byte) error
	Stat(context.Context, host.Host, string) (FileInfo, error)
	Canonicalize(context.Context, host.Host, string) (string, error)
	List(context.Context, host.Host, string) ([]DirEntry, error)
	Mkdir(context.Context, host.Host, string) error
	Rename(context.Context, host.Host, string, string) error
	Remove(context.Context, host.Host, string) error
	AtomicWrite(context.Context, host.Host, string, []byte) error
	ReadTree(context.Context, host.Host, string) ([]TreeEntry, error)
	WriteTree(context.Context, host.Host, string, []TreeEntry) error
}
