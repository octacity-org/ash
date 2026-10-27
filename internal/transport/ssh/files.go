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
	"time"
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

// streamCloseGrace is how long a cancelled streamed transfer may keep its
// SFTP session to clean up, such as removing an atomic temporary file, before
// the session is closed under it.
const streamCloseGrace = 5 * time.Second

// streamFiles opens an SFTP session for one streamed transfer. Unlike the
// pooled session, it is closed when the context ends and the transfer has not
// finished within streamCloseGrace, which unblocks a stalled request.
func (t *Transport) streamFiles(ctx context.Context, h host.Host) (*sftp.Client, func(), error) {
	var fs *sftp.Client
	var cleanup func()
	if t.newSFTPDial != nil {
		var err error
		if fs, cleanup, err = t.newSFTPDial(ctx, h); err != nil {
			return nil, nil, err
		}
	} else {
		client, release, err := t.connect(ctx, h)
		if err != nil {
			return nil, nil, err
		}
		if fs, err = sftp.NewClient(client); err != nil {
			release()
			return nil, nil, operationError(ctx, err)
		}
		cleanup = func() { fs.Close(); release() }
	}
	done := make(chan struct{})
	stop := context.AfterFunc(ctx, func() {
		select {
		case <-done:
		case <-time.After(streamCloseGrace):
			fs.Close()
		}
	})
	return fs, func() { close(done); stop(); cleanup() }, nil
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

// ReadStream copies a whole remote file to w without a size limit.
func (t *Transport) ReadStream(ctx context.Context, h host.Host, p string, w io.Writer) error {
	fs, cleanup, err := t.streamFiles(ctx, h)
	if err != nil {
		return err
	}
	defer cleanup()
	p, err = remotePath(fs, p)
	if err != nil {
		return operationError(ctx, err)
	}
	file, err := fs.Open(p)
	if err != nil {
		return operationError(ctx, err)
	}
	defer file.Close()
	_, err = io.Copy(w, file)
	return operationError(ctx, err)
}

// WriteStream creates or truncates a remote file from r without a size
// limit. A failed plain write may leave a partial file; an atomic one leaves
// the destination untouched.
func (t *Transport) WriteStream(ctx context.Context, h host.Host, p string, r io.Reader, atomic bool) error {
	fs, cleanup, err := t.streamFiles(ctx, h)
	if err != nil {
		return err
	}
	defer cleanup()
	p, err = remotePath(fs, p)
	if err != nil {
		return operationError(ctx, err)
	}
	if atomic {
		return operationError(ctx, atomicWriteSFTP(clientDialer{fs}, p, r))
	}
	file, err := fs.OpenFile(p, os.O_WRONLY|os.O_CREATE|os.O_TRUNC)
	if err != nil {
		return operationError(ctx, err)
	}
	_, copyErr := io.Copy(file, r)
	closeErr := file.Close()
	if copyErr != nil {
		return operationError(ctx, copyErr)
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
