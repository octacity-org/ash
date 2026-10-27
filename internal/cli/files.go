package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"

	"ash/internal/service"
	"ash/internal/transport"
)

func encodeOK(out io.Writer, fail func(error) int) int {
	if err := json.NewEncoder(out).Encode(map[string]bool{"ok": true}); err != nil {
		return fail(err)
	}
	return 0
}

// runRead writes a whole file, or a slice when --offset or --limit is given.
func runRead(ctx context.Context, args []string, s *service.Service, out io.Writer) error {
	if len(args) < 2 {
		return fmt.Errorf("read requires HOST PATH [--offset N] [--limit N]")
	}
	var offset, limit int64
	ranged := false
	for i := 2; i < len(args); i++ {
		key, value, hasValue := strings.Cut(args[i], "=")
		if key != "--offset" && key != "--limit" {
			return fmt.Errorf("unknown read option %q", args[i])
		}
		if !hasValue {
			i++
			if i == len(args) {
				return fmt.Errorf("%s requires a value", key)
			}
			value = args[i]
		}
		n, err := strconv.ParseInt(value, 10, 64)
		if err != nil {
			return fmt.Errorf("%s requires an integer", key)
		}
		if key == "--offset" {
			offset = n
		} else {
			limit = n
		}
		ranged = true
	}
	var data []byte
	if ranged {
		r, err := s.ReadRange(ctx, args[0], args[1], offset, limit)
		if err != nil {
			return err
		}
		data = r.Data
	} else {
		var err error
		if data, err = s.Read(ctx, args[0], args[1]); err != nil {
			return err
		}
	}
	_, err := out.Write(data)
	return err
}

func runWrite(ctx context.Context, args []string, s *service.Service, in io.Reader) error {
	if len(args) < 2 {
		return fmt.Errorf("write requires HOST PATH [--atomic]")
	}
	atomic := false
	for _, arg := range args[2:] {
		if arg != "--atomic" {
			return fmt.Errorf("unknown write option %q", arg)
		}
		atomic = true
	}
	data, err := readInput(ctx, in, transport.MaxWriteSize)
	if err != nil {
		return err
	}
	if atomic {
		return s.AtomicWrite(ctx, args[0], args[1], data)
	}
	return s.Write(ctx, args[0], args[1], data)
}

// runDownload maps a bounded remote tree onto a local directory. It never
// follows remote symlinks and refuses to write outside the local root.
//
// Lexical containment alone is not enough locally: MkdirAll and WriteFile
// follow existing symlinks, so a pre-existing symlinked directory inside the
// destination could redirect a tree entry outside the root. Every destination
// component is therefore checked with Lstat and any existing symlink in the
// path is refused.
func runDownload(ctx context.Context, args []string, s *service.Service) error {
	if len(args) != 3 {
		return fmt.Errorf("download requires HOST REMOTE_DIR LOCAL_DIR")
	}
	entries, err := s.ReadTree(ctx, args[0], args[1])
	if err != nil {
		return err
	}
	root := args[2]
	for _, entry := range entries {
		target := filepath.Join(root, filepath.FromSlash(entry.Path))
		relative, err := filepath.Rel(root, target)
		if err != nil || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
			return fmt.Errorf("refusing to write %q outside %q", entry.Path, root)
		}
		if entry.IsDir {
			if err := mkdirAllSafe(target, root); err != nil {
				return err
			}
			continue
		}
		if err := mkdirAllSafe(filepath.Dir(target), root); err != nil {
			return err
		}
		file, err := openNewFile(target)
		if err != nil {
			return err
		}
		if _, err := file.Write(entry.Data); err != nil {
			file.Close()
			return err
		}
		if runtime.GOOS != "windows" {
			perm := entry.Perm
			if perm == 0 {
				perm = 0o644
			}
			if err := file.Chmod(perm); err != nil {
				file.Close()
				return err
			}
		}
		if err := file.Close(); err != nil {
			return err
		}
	}
	return nil
}

// mkdirAllSafe creates dir and any missing parents up to and including root,
// refusing to traverse an existing symlink component. The destination root is
// created when missing - including its missing ancestors - so a download into
// a new directory works instead of failing on its first child.
func mkdirAllSafe(dir, root string) error {
	if dir == root {
		return mkdirComponent(dir, true)
	}
	if dir == string(filepath.Separator) || dir == "." {
		return ensureNotSymlink(dir)
	}
	parent := filepath.Dir(dir)
	if parent != dir {
		if err := mkdirAllSafe(parent, root); err != nil {
			return err
		}
	}
	return mkdirComponent(dir, false)
}

// mkdirComponent ensures dir exists as a real directory, creating it when
// missing. Every existing component is checked with Lstat, so a symlink is
// never traversed. When withAncestors is set, missing parents are created the
// same way; it is used for the destination root, whose ancestors may also be
// missing.
func mkdirComponent(dir string, withAncestors bool) error {
	if err := ensureNotSymlink(dir); err != nil {
		return err
	}
	info, err := os.Lstat(dir)
	switch {
	case err == nil && info.IsDir():
		return nil
	case err == nil:
		return fmt.Errorf("%q exists and is not a directory", dir)
	case !errors.Is(err, os.ErrNotExist):
		return err
	}
	if withAncestors {
		parent := filepath.Dir(dir)
		if parent != dir {
			if err := mkdirComponent(parent, true); err != nil {
				return err
			}
		}
	}
	return os.Mkdir(dir, 0o755)
}

// ensureNotSymlink rejects a path whose final component is a symlink.
func ensureNotSymlink(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("refusing to follow symlink %q", path)
	}
	return nil
}

// openNewFile opens target for writing without following a symlink placed at
// the path (before or during the open). On POSIX, O_NOFOLLOW makes the kernel
// refuse symlink finals atomically; Windows relies on the earlier Lstat walk
// plus os.OpenFile not creating symlink entries itself.
func openNewFile(target string) (*os.File, error) {
	if err := ensureNotSymlink(target); err != nil {
		return nil, err
	}
	file, err := openNoFollow(target)
	if err != nil {
		if errors.Is(err, errSymlinkRefused) {
			return nil, fmt.Errorf("refusing to write through symlink %q", target)
		}
		return nil, err
	}
	return file, nil
}

// runUpload maps a local directory onto a bounded remote tree, skipping symlinks.
func runUpload(ctx context.Context, args []string, s *service.Service) error {
	if len(args) != 3 {
		return fmt.Errorf("upload requires HOST LOCAL_DIR REMOTE_DIR")
	}
	entries, err := walkLocal(args[1])
	if err != nil {
		return err
	}
	return s.WriteTree(ctx, args[0], args[2], entries)
}

func walkLocal(root string) ([]transport.TreeEntry, error) {
	info, err := os.Stat(root)
	if err != nil {
		return nil, err
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("upload source must be a directory")
	}
	entries := make([]transport.TreeEntry, 0)
	total := 0
	type item struct {
		absolute string
		relative string
		depth    int
	}
	stack := []item{{absolute: root}}
	for len(stack) > 0 {
		current := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		children, err := os.ReadDir(current.absolute)
		if err != nil {
			return nil, err
		}
		sort.Slice(children, func(i, j int) bool { return children[i].Name() < children[j].Name() })
		subdirs := make([]item, 0, len(children))
		for _, child := range children {
			if child.Type()&os.ModeSymlink != 0 {
				continue
			}
			relative := child.Name()
			if current.relative != "" {
				relative = current.relative + "/" + child.Name()
			}
			absolute := filepath.Join(current.absolute, child.Name())
			if child.IsDir() {
				if current.depth+1 > transport.MaxTreeDepth {
					return nil, fmt.Errorf("upload exceeds depth %d", transport.MaxTreeDepth)
				}
				entries = append(entries, transport.TreeEntry{Path: relative, IsDir: true})
				subdirs = append(subdirs, item{absolute: absolute, relative: relative, depth: current.depth + 1})
			} else {
				childInfo, err := child.Info()
				if err != nil {
					return nil, err
				}
				if childInfo.Size() > transport.MaxReadSize {
					return nil, fmt.Errorf("file %q exceeds %d byte limit", relative, transport.MaxReadSize)
				}
				data, err := os.ReadFile(absolute)
				if err != nil {
					return nil, err
				}
				total += len(data)
				if total > transport.MaxTreePayload {
					return nil, fmt.Errorf("upload exceeds %d byte payload", transport.MaxTreePayload)
				}
				entry := transport.TreeEntry{Path: relative, Data: data}
				// Windows has no POSIX permission bits; its uploads keep the
				// 0644 default.
				if runtime.GOOS != "windows" {
					entry.Perm = childInfo.Mode().Perm()
				}
				entries = append(entries, entry)
			}
			if len(entries) > transport.MaxTreeEntries {
				return nil, fmt.Errorf("upload exceeds %d entries", transport.MaxTreeEntries)
			}
		}
		for i := len(subdirs) - 1; i >= 0; i-- {
			stack = append(stack, subdirs[i])
		}
	}
	return entries, nil
}
