package ssh

import (
	"ash/internal/host"
	"ash/internal/transport"
	"context"
	"fmt"
	"github.com/pkg/sftp"
	"io"
	"os"
	"path"
	"strings"
)

func (t *Transport) files(ctx context.Context, h host.Host) (*sftp.Client, func(), error) {
	if t.newSFTPDial != nil {
		// Test seam: the SFTP client is provided directly instead of being
		// opened over a dialed SSH connection.
		return t.newSFTPDial(ctx, h)
	}
	if t.dialOverride != nil {
		client, cleanup, err := t.connect(ctx, h)
		if err != nil {
			return nil, nil, err
		}
		fs, err := sftp.NewClient(client)
		if err != nil {
			cleanup()
			return nil, nil, operationError(ctx, err)
		}
		return fs, func() { fs.Close(); cleanup() }, nil
	}
	if err := ctx.Err(); err != nil {
		return nil, nil, operationError(ctx, err)
	}
	// Pooled connections keep their SFTP session, so consecutive file
	// operations (such as a root check and the read) share one subsystem.
	res, release, err := t.claim(ctx, h)
	if err != nil {
		return nil, nil, err
	}
	fs, err := res.sftpClient()
	if err != nil {
		release()
		return nil, nil, operationError(ctx, err)
	}
	return fs, release, nil
}
func remotePath(fs *sftp.Client, p string) (string, error) {
	if p == "" || strings.ContainsRune(p, 0) {
		return "", fmt.Errorf("path must be nonempty and contain no NUL")
	}
	if p == "~" || strings.HasPrefix(p, "~/") {
		home, err := fs.Getwd()
		if err != nil {
			return "", err
		}
		if p == "~" {
			return home, nil
		}
		return path.Join(home, p[2:]), nil
	}
	return p, nil
}
func (t *Transport) Read(ctx context.Context, h host.Host, p string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, transport.DefaultFileTimeout)
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
	file, err := fs.Open(p)
	if err != nil {
		return nil, operationError(ctx, err)
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, transport.MaxReadSize+1))
	if err != nil {
		return nil, operationError(ctx, err)
	}
	if len(data) > transport.MaxReadSize {
		return nil, transport.ErrTooLarge
	}
	return data, nil
}

// ReadRange seeks within the file instead of loading it, so slices of files
// larger than MaxReadSize can be read.
func (t *Transport) ReadRange(ctx context.Context, h host.Host, p string, offset, limit int64) (transport.FileRange, error) {
	ctx, cancel := context.WithTimeout(ctx, transport.DefaultFileTimeout)
	defer cancel()
	fs, cleanup, err := t.files(ctx, h)
	if err != nil {
		return transport.FileRange{}, err
	}
	defer cleanup()
	p, err = remotePath(fs, p)
	if err != nil {
		return transport.FileRange{}, operationError(ctx, err)
	}
	file, err := fs.Open(p)
	if err != nil {
		return transport.FileRange{}, operationError(ctx, err)
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return transport.FileRange{}, operationError(ctx, err)
	}
	size := info.Size()
	start := min(offset, size)
	if offset < 0 {
		start = max(size+offset, 0)
	}
	if _, err := file.Seek(start, io.SeekStart); err != nil {
		return transport.FileRange{}, operationError(ctx, err)
	}
	data, err := io.ReadAll(io.LimitReader(file, limit))
	if err != nil {
		return transport.FileRange{}, operationError(ctx, err)
	}
	return transport.FileRange{Data: data, Offset: start, Size: size}, nil
}
func (t *Transport) Write(ctx context.Context, h host.Host, p string, data []byte) error {
	if len(data) > transport.MaxWriteSize {
		return transport.ErrTooLarge
	}
	ctx, cancel := context.WithTimeout(ctx, transport.DefaultFileTimeout)
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
	file, err := fs.OpenFile(p, os.O_WRONLY|os.O_CREATE|os.O_TRUNC)
	if err != nil {
		return operationError(ctx, err)
	}
	_, writeErr := file.Write(data)
	closeErr := file.Close()
	if writeErr != nil {
		return operationError(ctx, writeErr)
	}
	return operationError(ctx, closeErr)
}
func (t *Transport) Stat(ctx context.Context, h host.Host, p string) (transport.FileInfo, error) {
	ctx, cancel := context.WithTimeout(ctx, transport.DefaultFileTimeout)
	defer cancel()
	fs, cleanup, err := t.files(ctx, h)
	if err != nil {
		return transport.FileInfo{}, err
	}
	defer cleanup()
	p, err = remotePath(fs, p)
	if err != nil {
		return transport.FileInfo{}, operationError(ctx, err)
	}
	info, err := fs.Stat(p)
	if err != nil {
		return transport.FileInfo{}, operationError(ctx, err)
	}
	return transport.FileInfo{Path: p, Size: info.Size(), Mode: info.Mode().String(), ModTime: info.ModTime(), IsDir: info.IsDir()}, nil
}
