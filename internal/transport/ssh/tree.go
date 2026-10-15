package ssh

import (
	"ash/internal/host"
	"ash/internal/transport"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"sort"

	"github.com/pkg/sftp"
)

func (t *Transport) fileTimeout(ctx context.Context) (context.Context, context.CancelFunc) {
	return context.WithTimeout(ctx, transport.DefaultFileTimeout)
}

// List returns the sorted direct children of a remote directory.
func (t *Transport) List(ctx context.Context, h host.Host, p string) ([]transport.DirEntry, error) {
	ctx, cancel := t.fileTimeout(ctx)
	defer cancel()
	fs, cleanup, err := t.files(ctx, h)
	if err != nil {
		return nil, err
	}
	defer cleanup()
	p, err = remotePath(fs, p)
	if err != nil {
		return nil, operationError(ctx, err)
	}
	infos, err := fs.ReadDir(p)
	if err != nil {
		return nil, operationError(ctx, err)
	}
	entries := make([]transport.DirEntry, 0, len(infos))
	for _, info := range infos {
		mode := info.Mode()
		entries = append(entries, transport.DirEntry{
			Name:    info.Name(),
			Path:    path.Join(p, info.Name()),
			Size:    info.Size(),
			Mode:    mode.String(),
			ModTime: info.ModTime(),
			IsDir:   mode.IsDir(),
			Symlink: mode&os.ModeSymlink != 0,
		})
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Name < entries[j].Name })
	return entries, nil
}

// Mkdir creates one directory; parents must already exist.
func (t *Transport) Mkdir(ctx context.Context, h host.Host, p string) error {
	ctx, cancel := t.fileTimeout(ctx)
	defer cancel()
	fs, cleanup, err := t.files(ctx, h)
	if err != nil {
		return err
	}
	defer cleanup()
	p, err = remotePath(fs, p)
	if err != nil {
		return operationError(ctx, err)
	}
	return operationError(ctx, fs.Mkdir(p))
}

// Rename moves a file or directory within the same SFTP server.
func (t *Transport) Rename(ctx context.Context, h host.Host, from, to string) error {
	ctx, cancel := t.fileTimeout(ctx)
	defer cancel()
	fs, cleanup, err := t.files(ctx, h)
	if err != nil {
		return err
	}
	defer cleanup()
	from, err = remotePath(fs, from)
	if err != nil {
		return operationError(ctx, err)
	}
	to, err = remotePath(fs, to)
	if err != nil {
		return operationError(ctx, err)
	}
	return operationError(ctx, fs.Rename(from, to))
}

// Remove deletes a file or an empty directory. It is never recursive.
func (t *Transport) Remove(ctx context.Context, h host.Host, p string) error {
	ctx, cancel := t.fileTimeout(ctx)
	defer cancel()
	fs, cleanup, err := t.files(ctx, h)
	if err != nil {
		return err
	}
	defer cleanup()
	p, err = remotePath(fs, p)
	if err != nil {
		return operationError(ctx, err)
	}
	return operationError(ctx, fs.Remove(p))
}

// AtomicWrite replaces p completely or leaves the prior file intact by writing
// a same-directory temporary file, syncing, and renaming it into place.
//
// Replacement requires atomic rename-over-existing, which the SFTP RENAME
// operation does not provide: OpenSSH fails it with SSH_FX_FAILURE when the
// target exists. The posix-rename@openssh.com extension performs a real
// POSIX rename and is used instead; without it, no atomic replacement exists
// and the operation fails rather than risking a delete-then-rename window
// that would leave the destination missing on failure.
func (t *Transport) AtomicWrite(ctx context.Context, h host.Host, p string, data []byte) error {
	if len(data) > transport.MaxWriteSize {
		return transport.ErrTooLarge
	}
	ctx, cancel := t.fileTimeout(ctx)
	defer cancel()
	fs, cleanup, err := t.files(ctx, h)
	if err != nil {
		return err
	}
	defer cleanup()
	p, err = remotePath(fs, p)
	if err != nil {
		return operationError(ctx, err)
	}
	return operationError(ctx, atomicWriteSFTP(clientDialer{fs}, p, data))
}

// sftpDialer abstracts the part of the SFTP client used by the atomic write,
// so tests can simulate servers lacking the posix-rename extension.
// clientFile wraps *sftp.File, whose concrete OpenFile return type prevents
// *sftp.Client from implementing this interface directly.
type sftpFile interface {
	Write([]byte) (int, error)
	Sync() error
	Chmod(os.FileMode) error
	Close() error
}

type clientFile struct{ *sftp.File }

type sftpDialer interface {
	OpenFile(path string, f int) (sftpFile, error)
	PosixRename(oldname, newname string) error
	Remove(path string) error
	Stat(path string) (os.FileInfo, error)
}

// clientDialer adapts *sftp.Client to sftpDialer.
type clientDialer struct{ *sftp.Client }

func (c clientDialer) OpenFile(path string, f int) (sftpFile, error) {
	file, err := c.Client.OpenFile(path, f)
	if err != nil {
		return nil, err
	}
	return clientFile{file}, nil
}

// atomicWriteSFTP writes data to a same-directory temporary file and renames
// it over p atomically, or leaves p untouched: the temp file is always
// removed on failure, and the rename never deletes the destination first.
func atomicWriteSFTP(fs sftpDialer, p string, data []byte) error {
	var random [8]byte
	if _, err := rand.Read(random[:]); err != nil {
		return err
	}
	temp := path.Join(path.Dir(p), ".ash-tmp-"+hex.EncodeToString(random[:]))
	file, err := fs.OpenFile(temp, os.O_WRONLY|os.O_CREATE|os.O_EXCL)
	if err != nil {
		return err
	}
	removeTemp := true
	defer func() {
		if removeTemp {
			fs.Remove(temp)
		}
	}()
	closeWith := func(err error) error {
		file.Close()
		return err
	}
	if _, err := file.Write(data); err != nil {
		return closeWith(err)
	}
	if err := file.Sync(); err != nil && !isUnsupportedOperation(err) {
		// fsync@openssh.com is a durability optimization; servers without it
		// still get correct atomicity from the rename below, so its absence
		// is not an error.
		return closeWith(err)
	}
	// Keep the replaced file's permission bits; only a new file gets 0644.
	// Ownership cannot be preserved without privileges.
	mode := os.FileMode(0644)
	if info, err := fs.Stat(p); err == nil && info.Mode().IsRegular() {
		mode = info.Mode().Perm()
	}
	if err := file.Chmod(mode); err != nil {
		return closeWith(err)
	}
	if err := file.Close(); err != nil {
		return err
	}
	if err := fs.PosixRename(temp, p); err != nil {
		// A server that does not implement the extension answers with
		// SSH_FX_OP_UNSUPPORTED; other status codes are real failures. In
		// neither case is the destination touched.
		if isUnsupportedOperation(err) {
			return fmt.Errorf("atomic replacement is not supported by this SFTP server (missing posix-rename@openssh.com extension): %w", err)
		}
		return err
	}
	removeTemp = false
	return nil
} // isUnsupportedOperation reports whether an SFTP error means the server does
// not implement the requested operation or extension.
func isUnsupportedOperation(err error) bool {
	var status *sftp.StatusError
	if errors.As(err, &status) {
		return status.FxCode() == sftp.ErrSSHFxOpUnsupported
	}
	return errors.Is(err, sftp.ErrSSHFxOpUnsupported)
}

type treeItem struct {
	absolute string
	relative string
	depth    int
}

// ReadTree walks a remote directory iteratively without following symlinks,
// bounded by entry count, total bytes, and depth.
func (t *Transport) ReadTree(ctx context.Context, h host.Host, root string) ([]transport.TreeEntry, error) {
	ctx, cancel := t.fileTimeout(ctx)
	defer cancel()
	fs, cleanup, err := t.files(ctx, h)
	if err != nil {
		return nil, err
	}
	defer cleanup()
	root, err = remotePath(fs, root)
	if err != nil {
		return nil, operationError(ctx, err)
	}
	info, err := fs.Stat(root)
	if err != nil {
		return nil, operationError(ctx, err)
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("tree root must be a directory")
	}
	entries := make([]transport.TreeEntry, 0)
	total := 0
	stack := []treeItem{{absolute: root}}
	for len(stack) > 0 {
		item := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		infos, err := fs.ReadDir(item.absolute)
		if err != nil {
			return nil, operationError(ctx, err)
		}
		sort.Slice(infos, func(i, j int) bool { return infos[i].Name() < infos[j].Name() })
		children := make([]treeItem, 0, len(infos))
		for _, child := range infos {
			mode := child.Mode()
			if mode&os.ModeSymlink != 0 {
				continue
			}
			relative := child.Name()
			if item.relative != "" {
				relative = item.relative + "/" + child.Name()
			}
			absolute := path.Join(item.absolute, child.Name())
			if mode.IsDir() {
				if item.depth+1 > transport.MaxTreeDepth {
					return nil, fmt.Errorf("tree exceeds depth %d", transport.MaxTreeDepth)
				}
				entries = append(entries, transport.TreeEntry{Path: relative, Mode: mode.String(), IsDir: true})
				children = append(children, treeItem{absolute: absolute, relative: relative, depth: item.depth + 1})
			} else {
				data, err := readTreeFile(fs, absolute)
				if err != nil {
					return nil, operationError(ctx, err)
				}
				total += len(data)
				if total > transport.MaxTreePayload {
					return nil, fmt.Errorf("tree exceeds %d byte payload", transport.MaxTreePayload)
				}
				entries = append(entries, transport.TreeEntry{Path: relative, Mode: mode.String(), Data: data})
			}
			if len(entries) > transport.MaxTreeEntries {
				return nil, fmt.Errorf("tree exceeds %d entries", transport.MaxTreeEntries)
			}
		}
		for i := len(children) - 1; i >= 0; i-- {
			stack = append(stack, children[i])
		}
	}
	return entries, nil
}

// WriteTree creates directories before files and rejects unsafe paths and type
// conflicts before the first remote mutation.
func (t *Transport) WriteTree(ctx context.Context, h host.Host, root string, entries []transport.TreeEntry) error {
	if err := transport.ValidateTree(root, entries); err != nil {
		return err
	}
	ctx, cancel := t.fileTimeout(ctx)
	defer cancel()
	fs, cleanup, err := t.files(ctx, h)
	if err != nil {
		return err
	}
	defer cleanup()
	root, err = remotePath(fs, root)
	if err != nil {
		return operationError(ctx, err)
	}
	if err := fs.MkdirAll(root); err != nil {
		return operationError(ctx, err)
	}
	dirs := make([]transport.TreeEntry, 0)
	files := make([]transport.TreeEntry, 0)
	for _, entry := range entries {
		if entry.IsDir {
			dirs = append(dirs, entry)
		} else {
			files = append(files, entry)
		}
	}
	sort.Slice(dirs, func(i, j int) bool { return dirs[i].Path < dirs[j].Path })
	sort.Slice(files, func(i, j int) bool { return files[i].Path < files[j].Path })
	for _, dir := range dirs {
		target := path.Join(root, dir.Path)
		if err := fs.Mkdir(target); err != nil {
			if info, statErr := fs.Stat(target); statErr != nil || !info.IsDir() {
				return operationError(ctx, err)
			}
		}
	}
	for _, file := range files {
		target := path.Join(root, file.Path)
		if err := fs.MkdirAll(path.Dir(target)); err != nil {
			return operationError(ctx, err)
		}
		f, err := fs.OpenFile(target, os.O_WRONLY|os.O_CREATE|os.O_TRUNC)
		if err != nil {
			return operationError(ctx, err)
		}
		if _, err := f.Write(file.Data); err != nil {
			f.Close()
			return operationError(ctx, err)
		}
		if err := f.Chmod(0644); err != nil {
			f.Close()
			return operationError(ctx, err)
		}
		if err := f.Close(); err != nil {
			return operationError(ctx, err)
		}
	}
	return nil
}

func readTreeFile(fs *sftp.Client, p string) ([]byte, error) {
	file, err := fs.Open(p)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, transport.MaxReadSize+1))
	if err != nil {
		return nil, err
	}
	if len(data) > transport.MaxReadSize {
		return nil, transport.ErrTooLarge
	}
	return data, nil
}
