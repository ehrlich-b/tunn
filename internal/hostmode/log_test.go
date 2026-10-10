package hostmode

import (
	"os"
	"path/filepath"
	"testing"
)

func TestBoundedLogs(t *testing.T) {
	p := filepath.Join(t.TempDir(), "host.log")
	// A stale file from an older daemon must not defeat the bound at startup.
	for _, path := range []string{p, p + ".1"} {
		if err := os.WriteFile(path, make([]byte, 1000), 0600); err != nil {
			t.Fatal(err)
		}
	}
	l, err := OpenLog(p, 32)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 100; i++ {
		if _, err := l.Write([]byte("a log record\n")); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := l.Write(make([]byte, 1000)); err != nil {
		t.Fatal(err)
	}
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{p, p + ".1"} {
		st, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if st.Size() > 32 {
			t.Fatalf("unbounded log: %d", st.Size())
		}
		if st.Mode().Perm() != 0600 {
			t.Fatalf("log permissions: %v", st.Mode())
		}
	}
}
