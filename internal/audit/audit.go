// Package audit appends structured, local JSONL records of ASH operations.
//
// Records intentionally omit command text, argv values, paths, file contents,
// environment variables, credentials, and process output.
package audit

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

type Decision string

const (
	Allowed Decision = "allowed"
	Denied  Decision = "denied"
)

type Result string

const (
	ResultOK      Result = "ok"
	ResultError   Result = "error"
	ResultTimeout Result = "timeout"
)

// Record is one bounded, redacted audit entry.
type Record struct {
	Time       time.Time `json:"time"`
	Operation  string    `json:"operation"`
	Host       string    `json:"host"`
	Decision   Decision  `json:"decision"`
	Result     Result    `json:"result"`
	DurationMS int64     `json:"duration_ms"`
	// BytesIn counts payload sent to the remote host (stdin, written content,
	// shell input); BytesOut counts payload returned from it (process output,
	// read content, shell output). Truncated reports a bounded result.
	BytesIn   int64 `json:"bytes_in,omitempty"`
	BytesOut  int64 `json:"bytes_out,omitempty"`
	Truncated bool  `json:"truncated,omitempty"`
	// Target is the host:port a forwarded connection reached.
	Target string `json:"target,omitempty"`
}

// Recorder appends records to one owner-only file. It is safe for concurrent
// use and fail-open: a write error never fails the underlying operation.
type Recorder struct {
	path string
	mu   sync.Mutex
}

// New creates or opens an owner-only audit file.
func New(path string) (*Recorder, error) {
	if path == "" {
		return nil, fmt.Errorf("audit path must not be empty")
	}
	if path == "~" || strings.HasPrefix(path, "~/") {
		home, err := os.UserHomeDir()
		if err != nil {
			return nil, err
		}
		if path == "~" {
			path = home
		} else {
			path = filepath.Join(home, path[2:])
		}
	}
	if dir := filepath.Dir(path); dir != "" {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return nil, fmt.Errorf("create audit directory: %w", err)
		}
	}
	file, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
	if err != nil {
		return nil, fmt.Errorf("open audit file: %w", err)
	}
	if err := file.Chmod(0600); err != nil {
		file.Close()
		return nil, fmt.Errorf("secure audit file: %w", err)
	}
	return &Recorder{path: path}, file.Close()
}

// Record appends one entry, ignoring failures (fail-open).
func (r *Recorder) Record(record Record) {
	if r == nil {
		return
	}
	if record.Time.IsZero() {
		record.Time = time.Now().UTC()
	}
	data, err := json.Marshal(record)
	if err != nil {
		return
	}
	data = append(data, '\n')
	r.mu.Lock()
	defer r.mu.Unlock()
	file, err := os.OpenFile(r.path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
	if err != nil {
		return
	}
	_, _ = file.Write(data)
	_ = file.Close()
}
