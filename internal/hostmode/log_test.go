package hostmode

import (
	"os"
	"path/filepath"
	"testing"
)

func TestBoundedLogs(t *testing.T) {
	p := filepath.Join(t.TempDir(), "host.log")
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
