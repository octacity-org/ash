// Package policy defines the capabilities granted to a configured host.
package policy

import (
	"errors"
	"fmt"
	"path"
	"strings"
	"time"
)

var ErrPermissionDenied = errors.New("operation not allowed")

// Compiled hard caps. Configurable bounds must stay at or below these.
const (
	HardMaxTimeoutSeconds = 300
	HardMaxInputBytes     = 64 << 10
	HardMaxOutputBytes    = 8 << 20
)

// Policy gates remote operations. The boolean capabilities are backward
// compatible; the optional fields add enforcement and are empty by default,
// preserving the previous broad behavior.
type Policy struct {
	Exec  bool `toml:"exec" json:"exec"`
	Read  bool `toml:"read" json:"read"`
	Write bool `toml:"write" json:"write"`

	// Remote absolute POSIX roots. Empty means unconstrained.
	ReadRoots  []string `toml:"read_roots,omitempty" json:"read_roots,omitempty"`
	WriteRoots []string `toml:"write_roots,omitempty" json:"write_roots,omitempty"`
	CwdRoots   []string `toml:"cwd_roots,omitempty" json:"cwd_roots,omitempty"`

	// AllowedCommands restricts argv-mode executables. When set, shell-code
	// execution is refused unless AllowShell is true.
	AllowedCommands []string `toml:"allowed_commands,omitempty" json:"allowed_commands,omitempty"`
	AllowShell      bool     `toml:"allow_shell,omitempty" json:"allow_shell,omitempty"`

	MaxTimeoutSeconds int   `toml:"max_timeout_seconds,omitempty" json:"max_timeout_seconds,omitempty"`
	MaxInputBytes     int64 `toml:"max_input_bytes,omitempty" json:"max_input_bytes,omitempty"`
	MaxOutputBytes    int64 `toml:"max_output_bytes,omitempty" json:"max_output_bytes,omitempty"`
	// MaxStreamBytes caps the bytes one streamed operation moves in both
	// directions combined. Zero means unlimited.
	MaxStreamBytes int64 `toml:"max_stream_bytes,omitempty" json:"max_stream_bytes,omitempty"`
}

func (p Policy) Check(operation string) error {
	allowed := false
	switch operation {
	case "exec":
		allowed = p.Exec
	case "read", "stat":
		allowed = p.Read
	case "write":
		allowed = p.Write
	}
	if !allowed {
		return ErrPermissionDenied
	}
	return nil
}

// MaxTimeout is the configured cap, or zero for no cap.
func (p Policy) MaxTimeout() time.Duration {
	if p.MaxTimeoutSeconds <= 0 {
		return 0
	}
	return time.Duration(p.MaxTimeoutSeconds) * time.Second
}

// CheckShell refuses shell-code execution when executable constraints exist and
// the operator has not explicitly accepted that shell code bypasses them.
func (p Policy) CheckShell() error {
	if len(p.AllowedCommands) > 0 && !p.AllowShell {
		return fmt.Errorf("%w: command constraints are configured; use argv execution or set allow_shell = true (which bypasses executable restrictions)", ErrPermissionDenied)
	}
	return nil
}

// CheckExecutable verifies an argv program against allowed_commands. A shell
// allowlist cannot be enforced, so this applies to argv mode only.
//
// An entry containing "/" is an exact-path allowlist: the program must equal
// it after normalization, so allowing /usr/bin/git does not accept /tmp/git.
// A bare entry such as "git" is deliberately basename semantics: it matches
// the program name wherever it resides, because resolving which PATH entry
// would run is a property of the remote login shell, not of ASH.
func (p Policy) CheckExecutable(program string) error {
	if len(p.AllowedCommands) == 0 {
		return nil
	}
	base := path.Base(program)
	for _, allowed := range p.AllowedCommands {
		if strings.ContainsRune(allowed, '/') {
			if program == path.Clean(allowed) {
				return nil
			}
			continue
		}
		if base == allowed {
			return nil
		}
	}
	return fmt.Errorf("%w: executable %q is not allowed", ErrPermissionDenied, base)
}

// HasRoots reports whether a path root constraint applies to this direction.
func (p Policy) HasRoots(write bool) bool {
	if write {
		return len(p.WriteRoots) > 0
	}
	return len(p.ReadRoots) > 0
}

// CheckRoots enforces read/write roots against a canonical remote path.
func (p Policy) CheckRoots(canonical string, write bool) error {
	roots := p.ReadRoots
	if write {
		roots = p.WriteRoots
	}
	if len(roots) == 0 {
		return nil
	}
	for _, root := range roots {
		if within(root, canonical) {
			return nil
		}
	}
	return fmt.Errorf("%w: path %q is outside the allowed roots", ErrPermissionDenied, canonical)
}

// CheckCwd enforces cwd roots against a canonical remote path.
func (p Policy) CheckCwd(canonical string) error {
	if len(p.CwdRoots) == 0 {
		return nil
	}
	for _, root := range p.CwdRoots {
		if within(root, canonical) {
			return nil
		}
	}
	return fmt.Errorf("%w: cwd %q is outside the allowed roots", ErrPermissionDenied, canonical)
}

func (p Policy) CheckInput(n int) error {
	if p.MaxInputBytes > 0 && int64(n) > p.MaxInputBytes {
		return fmt.Errorf("%w: input exceeds %d bytes", ErrPermissionDenied, p.MaxInputBytes)
	}
	return nil
}

func (p Policy) CheckOutput(n int) error {
	if p.MaxOutputBytes > 0 && int64(n) > p.MaxOutputBytes {
		return fmt.Errorf("%w: output exceeds %d bytes", ErrPermissionDenied, p.MaxOutputBytes)
	}
	return nil
}

// Validate checks optional fields without changing empty-field behavior.
func (p Policy) Validate() error {
	for _, root := range allRoots(p) {
		if err := validateRoot(root); err != nil {
			return err
		}
	}
	for _, command := range p.AllowedCommands {
		if strings.TrimSpace(command) == "" || strings.ContainsRune(command, 0) {
			return fmt.Errorf("allowed_commands entries must be nonempty and contain no NUL")
		}
	}
	if p.MaxTimeoutSeconds < 0 || p.MaxTimeoutSeconds > HardMaxTimeoutSeconds {
		return fmt.Errorf("max_timeout_seconds must be between 0 and %d", HardMaxTimeoutSeconds)
	}
	if p.MaxInputBytes < 0 || p.MaxInputBytes > HardMaxInputBytes {
		return fmt.Errorf("max_input_bytes must be between 0 and %d", HardMaxInputBytes)
	}
	if p.MaxOutputBytes < 0 || p.MaxOutputBytes > HardMaxOutputBytes {
		return fmt.Errorf("max_output_bytes must be between 0 and %d", HardMaxOutputBytes)
	}
	if p.MaxStreamBytes < 0 {
		return fmt.Errorf("max_stream_bytes must not be negative")
	}
	return nil
}

func allRoots(p Policy) []string {
	roots := make([]string, 0)
	roots = append(roots, p.ReadRoots...)
	roots = append(roots, p.WriteRoots...)
	roots = append(roots, p.CwdRoots...)
	return roots
}

func validateRoot(root string) error {
	if root == "" || strings.ContainsRune(root, 0) {
		return fmt.Errorf("policy roots must be nonempty and contain no NUL")
	}
	if !strings.HasPrefix(root, "/") {
		return fmt.Errorf("policy root %q must be an absolute remote POSIX path", root)
	}
	if path.Clean(root) != root {
		return fmt.Errorf("policy root %q must be normalized", root)
	}
	return nil
}

func within(root, target string) bool {
	root = path.Clean(root)
	target = path.Clean(target)
	if root == "/" {
		// path.Clean leaves "/" as "/"; root+"/" would form "//" and reject
		// every absolute path. The filesystem root contains everything.
		return strings.HasPrefix(target, "/")
	}
	if root == target {
		return true
	}
	return strings.HasPrefix(target, root+"/")
}
