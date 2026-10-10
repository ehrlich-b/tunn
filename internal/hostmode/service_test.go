package hostmode

import (
	"encoding/xml"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestServiceGolden(t *testing.T) {
	for _, platform := range []string{"darwin", "linux", "windows"} {
		t.Run(platform, func(t *testing.T) {
			s := ServiceSpec{OS: platform, Home: "/home/owner", Binary: "/opt/tunn/bin/tunn", Config: "/home/owner/.config/tunn/host.yaml", Username: "OWNER\\bryan", UID: 501}
			got, err := s.Unit()
			if err != nil {
				t.Fatal(err)
			}
			want, err := os.ReadFile(filepath.Join("testdata", platform+".golden"))
			if err != nil {
				t.Fatal(err)
			}
			if got != string(want) {
				t.Fatalf("unit differs from %s golden:\n%s", platform, got)
			}
			if platform != "linux" {
				d := xml.NewDecoder(strings.NewReader(got))
				for {
					_, err := d.Token()
					if err == io.EOF {
						break
					}
					if err != nil {
						t.Fatal(err)
					}
				}
			}
		})
	}
}

func TestServiceEscaping(t *testing.T) {
	s := ServiceSpec{OS: "darwin", Binary: `/a & b/tunn`, Home: "/home/owner", Config: `/a<config>/host.yaml`}
	u, err := s.Unit()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(u, "&amp;") || !strings.Contains(u, "&lt;") {
		t.Fatal("XML paths not escaped")
	}
	if got := systemdArg(`/a %n/$x/"tunn"`); got != `"/a %%n/$$x/\"tunn\""` {
		t.Fatalf("systemd quoting = %s", got)
	}
	if got := windowsArg(`C:\a b\`); got != `"C:\a b\\"` {
		t.Fatalf("Windows quoting = %s", got)
	}
	s.Config = "bad\npath"
	if _, err := s.Unit(); err == nil {
		t.Fatal("newline injection allowed")
	}
}

func TestServiceInstallUninstall(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", "")
	s := ServiceSpec{OS: "linux", Home: t.TempDir(), Binary: "/opt/tunn", Config: "/tmp/host.yaml"}
	var calls [][]string
	run := func(name string, args ...string) ([]byte, error) {
		calls = append(calls, append([]string{name}, args...))
		return nil, nil
	}
	if _, err := s.Manage("install", run); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(s.Path()); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Manage("uninstall", run); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(s.Path()); !os.IsNotExist(err) {
		t.Fatal("unit was not removed")
	}
	want := [][]string{{"systemctl", "--user", "daemon-reload"}, {"systemctl", "--user", "enable", "--now", "tunn-host.service"}, {"systemctl", "--user", "disable", "--now", "tunn-host.service"}, {"systemctl", "--user", "daemon-reload"}}
	if !reflect.DeepEqual(calls, want) {
		t.Fatalf("commands = %v", calls)
	}
}
