package hostmode

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"
)

// BoundedLog retains at most two max-size files, even across daemon restarts.
type BoundedLog struct {
	mu    sync.Mutex
	path  string
	limit int64
	file  *os.File
	size  int64
}

func OpenLog(path string, limit int64) (*BoundedLog, error) {
	if limit <= 0 {
		return nil, fmt.Errorf("log limit must be positive")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return nil, err
	}
	l := &BoundedLog{path: path, limit: limit}
	if st, err := os.Stat(path + ".1"); err == nil && st.Size() > limit {
		if err := os.Remove(path + ".1"); err != nil {
			return nil, err
		}
	} else if err != nil && !os.IsNotExist(err) {
		return nil, err
	}
	if err := l.open(); err != nil {
		return nil, err
	}
	return l, nil
}

func (l *BoundedLog) open() error {
	f, err := os.OpenFile(l.path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
	if err != nil {
		return err
	}
	if err := f.Chmod(0600); err != nil {
		_ = f.Close()
		return err
	}
	st, err := f.Stat()
	if err != nil {
		_ = f.Close()
		return err
	}
	l.file, l.size = f, st.Size()
	if l.size > l.limit {
		if err := f.Truncate(0); err != nil {
			_ = f.Close()
			return err
		}
		l.size = 0
	}
	return nil
}

func (l *BoundedLog) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	length := len(p)
	if int64(len(p)) > l.limit {
		p = p[len(p)-int(l.limit):]
	}
	if l.size+int64(len(p)) > l.limit {
		if err := l.file.Close(); err != nil {
			return 0, err
		}
		if err := os.Remove(l.path + ".1"); err != nil && !os.IsNotExist(err) {
			return 0, err
		}
		if err := os.Rename(l.path, l.path+".1"); err != nil {
			return 0, err
		}
		if err := l.open(); err != nil {
			return 0, err
		}
	}
	n, err := l.file.Write(p)
	l.size += int64(n)
	if err != nil {
		return n, err
	}
	return length, nil
}

func (l *BoundedLog) Close() error { l.mu.Lock(); defer l.mu.Unlock(); return l.file.Close() }
