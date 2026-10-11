//go:build windows

package client

import (
	"context"
	"os"
	"path/filepath"
	"time"

	"golang.org/x/sys/windows"
)

func lockCredentials(ctx context.Context, dir string) (func(), error) {
	if err := prepareCredentialDirectory(dir); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(filepath.Join(dir, "credentials.lock"), os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, err
	}
	var overlapped windows.Overlapped
	for {
		err = windows.LockFileEx(windows.Handle(f.Fd()), windows.LOCKFILE_EXCLUSIVE_LOCK|windows.LOCKFILE_FAIL_IMMEDIATELY, 0, 1, 0, &overlapped)
		if err == nil {
			return func() { _ = windows.UnlockFileEx(windows.Handle(f.Fd()), 0, 1, 0, &overlapped); _ = f.Close() }, nil
		}
		if err != windows.ERROR_LOCK_VIOLATION {
			f.Close()
			return nil, err
		}
		select {
		case <-ctx.Done():
			f.Close()
			return nil, ctx.Err()
		case <-time.After(50 * time.Millisecond):
		}
	}
}

// Windows replacement durability relies on the filesystem and user ACLs.
func syncCredentialDirectory(string) error { return nil }
