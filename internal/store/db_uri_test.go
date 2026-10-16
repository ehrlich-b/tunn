package store

import (
	"database/sql"
	"os"
	"path/filepath"
	"testing"
)

func TestInitForTestEscapesTemporaryPath(t *testing.T) {
	base, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	tmpDir := filepath.Join(base, "uri#valid?percent%25")
	if err := os.Mkdir(tmpDir, 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("TMPDIR", tmpDir)

	var databases []*sql.DB
	var directories []string
	var files []os.FileInfo
	for range 2 {
		db, err := InitForTest()
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = db.Close() })
		databases = append(databases, db)

		var sequence int
		var name, path string
		if err := db.QueryRow("PRAGMA database_list").Scan(&sequence, &name, &path); err != nil {
			t.Fatal(err)
		}
		dir := filepath.Dir(path)
		if filepath.Dir(dir) != tmpDir || filepath.Base(path) != "test.db" {
			t.Fatalf("database path = %q, want test.db in its own directory under %q", path, tmpDir)
		}
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if !info.Mode().IsRegular() {
			t.Fatalf("database path %q is not a regular file", path)
		}
		directories = append(directories, dir)
		files = append(files, info)
	}
	if directories[0] == directories[1] || os.SameFile(files[0], files[1]) {
		t.Fatal("test databases share a directory or file")
	}
	for i, db := range databases {
		if err := db.Close(); err != nil {
			t.Fatal(err)
		}
		if _, err := os.Stat(directories[i]); !os.IsNotExist(err) {
			t.Errorf("database directory %q after Close: %v, want os.ErrNotExist", directories[i], err)
		}
	}
}
