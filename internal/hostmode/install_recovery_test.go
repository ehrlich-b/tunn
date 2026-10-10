package hostmode

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v4"
)

// All three executors model registered/running state without spawning a process.
type fixtureManager struct {
	spec           ServiceSpec
	loaded, active bool
	fail           string
	calls          int
}

func (f *fixtureManager) run(name string, args ...string) ([]byte, error) {
	f.calls++
	verb := args[0]
	if name == "systemctl" {
		verb = args[1]
	}
	if f.fail == verb {
		return nil, fmt.Errorf("fixture manager refused %s", verb)
	}
	switch name {
	case "launchctl":
		switch verb {
		case "print":
			if !f.loaded {
				return nil, errors.New("fixture job absent")
			}
		case "bootstrap":
			if f.loaded || args[2] != f.spec.Path() {
				return nil, errors.New("duplicate or wrong bootstrap path")
			}
			f.loaded, f.active = true, true
		case "bootout":
			if !f.loaded {
				return nil, errors.New("fixture job absent")
			}
			f.loaded, f.active = false, false
		case "kickstart":
			f.active = f.loaded
		default:
			return nil, fmt.Errorf("unexpected launchctl operation: %v", args)
		}
	case "systemctl":
		switch verb {
		case "show":
			if f.loaded {
				return []byte(f.spec.Path()), nil
			}
			return nil, nil
		case "daemon-reload":
		case "enable":
			f.loaded, f.active = true, true
		case "disable":
			f.loaded, f.active = false, false
		case "restart":
			f.active = f.loaded
		case "status":
			if !f.active {
				return nil, errors.New("fixture service offline")
			}
		default:
			return nil, fmt.Errorf("unexpected systemctl operation: %v", args)
		}
	case "schtasks":
		switch verb {
		case "/Query":
			if !f.loaded {
				return nil, errors.New("fixture task absent")
			}
		case "/Create":
			if f.loaded {
				return nil, errors.New("duplicate task must never be forced")
			}
			if args[4] != f.spec.Path() {
				return nil, errors.New("wrong task path")
			}
			f.loaded = true
		case "/Run":
			if !f.loaded {
				return nil, errors.New("fixture task absent")
			}
			f.active = true
		case "/End":
			f.active = false
		case "/Delete":
			f.loaded, f.active = false, false
		default:
			return nil, fmt.Errorf("unexpected schtasks operation: %v", args)
		}
	default:
		return nil, fmt.Errorf("real command forbidden in fixture: %s", name)
	}
	return []byte("fixture manager ok"), nil
}

func TestServiceInstallRecoveryFixtures(t *testing.T) {
	// A hostile inherited XDG path must not redirect an explicitly rooted fixture.
	t.Setenv("XDG_CONFIG_HOME", "relative-inherited-root")
	for _, platform := range []string{"darwin", "linux", "windows"} {
		t.Run(platform, func(t *testing.T) {
			root := filepath.Join(t.TempDir(), "owner with spaces")
			if err := os.MkdirAll(root, 0700); err != nil {
				t.Fatal(err)
			}
			s := ServiceSpec{OS: platform, Home: root, ConfigHome: filepath.Join(root, "explicit config"),
				Binary: filepath.Join(root, "bin with spaces", "tunn"), Config: filepath.Join(root, "host.yaml"), Username: "OWNER\\fixture", UID: 501}
			profile := []byte(validConfig)
			if err := os.WriteFile(s.Config, profile, 0600); err != nil {
				t.Fatal(err)
			}
			token := filepath.Join(root, "publisher.token")
			if err := os.WriteFile(token, []byte("existing-user-owned-credential"), 0600); err != nil {
				t.Fatal(err)
			}
			manager := &fixtureManager{spec: s}
			for i := 0; i < 2; i++ {
				if _, err := s.Manage("install", manager.run); err != nil || !manager.active {
					t.Fatalf("install %d: active=%v, %v", i, manager.active, err)
				}
			}
			before, err := os.ReadFile(s.Path())
			if err != nil {
				t.Fatal(err)
			}
			info, err := os.Stat(s.Path())
			if err != nil || info.Mode().Perm() != 0600 {
				t.Fatal("unit must be mode 0600")
			}
			other := s
			other.Binary += "-replacement"
			calls := manager.calls
			if _, err := other.Manage("install", manager.run); err == nil || calls != manager.calls {
				t.Fatal("conflicting installer changed prior registration")
			}
			if after, _ := os.ReadFile(s.Path()); !bytes.Equal(before, after) {
				t.Fatal("conflicting installer overwrote prior definition")
			}
			for _, action := range []string{"restart", "status", "uninstall", "uninstall"} {
				if _, err := s.Manage(action, manager.run); err != nil {
					t.Fatalf("%s: %v", action, err)
				}
			}
			if manager.loaded || manager.active {
				t.Fatal("removal left a fixture service running")
			}
			if got, _ := os.ReadFile(s.Config); !bytes.Equal(got, profile) {
				t.Fatal("host profile changed during installation/removal")
			}
			if got, _ := os.ReadFile(token); string(got) != "existing-user-owned-credential" {
				t.Fatal("publisher credential changed")
			}
			config, err := Load(s.Config)
			if err != nil || config.Machine != "gpu-box" || config.Tunnels[0].Name != "gpu-http" {
				t.Fatal("host ID or stable names changed")
			}
			// Model the manager failing after the complete definition was staged.
			manager.fail = map[string]string{"darwin": "bootstrap", "linux": "enable", "windows": "/Run"}[platform]
			if _, err := s.Manage("install", manager.run); err == nil {
				t.Fatal("manager failure was reported as success")
			}
			if got, _ := os.ReadFile(s.Path()); !bytes.Equal(got, before) {
				t.Fatal("failed install did not retain a complete recoverable definition")
			}
			manager.fail = ""
			if _, err := s.Manage("install", manager.run); err != nil || !manager.active {
				t.Fatalf("rerun did not reconcile staged definition: %v", err)
			}
			manager.fail = map[string]string{"darwin": "bootout", "linux": "disable", "windows": "/Delete"}[platform]
			if _, err := s.Manage("uninstall", manager.run); err == nil {
				t.Fatal("failed removal was reported as success")
			}
			if _, err := os.Stat(s.Path()); err != nil {
				t.Fatal("failed removal discarded recoverable definition")
			}
		})
	}
}

func TestServiceRefusesSymlinkAndForeignRemoval(t *testing.T) {
	root := t.TempDir()
	s := ServiceSpec{OS: "linux", Home: root, ConfigHome: root, Binary: "/opt/tunn", Config: filepath.Join(root, "host.yaml")}
	if err := os.MkdirAll(filepath.Dir(s.Path()), 0700); err != nil {
		t.Fatal(err)
	}
	foreign := filepath.Join(root, "foreign")
	if err := os.WriteFile(foreign, []byte("user service"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(foreign, s.Path()); err != nil {
		t.Fatal(err)
	}
	for _, action := range []string{"install", "restart", "uninstall"} {
		if _, err := s.Manage(action, func(string, ...string) ([]byte, error) {
			t.Fatal("foreign service touched its manager")
			return nil, nil
		}); err == nil {
			t.Fatal("symlinked definition accepted")
		}
	}
	if got, _ := os.ReadFile(foreign); string(got) != "user service" {
		t.Fatal("foreign file changed")
	}
}

func TestServiceRefusesPreexistingManagerRegistration(t *testing.T) {
	for _, platform := range []string{"linux", "windows"} {
		t.Run(platform, func(t *testing.T) {
			root := t.TempDir()
			s := ServiceSpec{OS: platform, Home: root, ConfigHome: root, Binary: "/opt/tunn", Config: filepath.Join(root, "host.yaml"), Username: "fixture"}
			manager := &fixtureManager{spec: s, loaded: true, active: true}
			if _, err := s.Manage("install", manager.run); err == nil {
				t.Fatal("foreign registered service was replaced")
			}
			if !manager.loaded || !manager.active {
				t.Fatal("foreign service was stopped")
			}
			if _, err := os.Stat(s.Path()); !os.IsNotExist(err) {
				t.Fatal("foreign service gained a misleading local definition")
			}
		})
	}
}

func TestHostRuntimePrivateCredentialFixtures(t *testing.T) {
	root := t.TempDir()
	t.Setenv("TUNN_CONFIG_DIR", root)
	path := filepath.Join(root, "token")
	c := &Config{TokenFile: path}
	if err := os.WriteFile(path, []byte("fixture-static-secret"), 0600); err != nil {
		t.Fatal(err)
	}
	for _, config := range []*Config{c, {}} {
		if got, err := Credentials(config); err != nil || got != "fixture-static-secret" {
			t.Fatal("existing private credential rejected", err)
		}
	}
	if err := os.Chmod(path, 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := Credentials(c); err == nil {
		t.Fatal("readable token file accepted")
	}
	info, err := os.Stat(path)
	if err != nil || info.Mode().Perm() != 0644 {
		t.Fatal("diagnostic repaired permissions without approval")
	}
	if err := os.Chmod(path, 0600); err != nil {
		t.Fatal(err)
	}
	for _, expiry := range []int64{time.Now().Unix() - 1, time.Now().Unix() + 3600} {
		jwtToken := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{"exp": expiry, "email": "fixture@example.test"})
		token, err := jwtToken.SignedString([]byte("fixture-key"))
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(token), 0600); err != nil {
			t.Fatal(err)
		}
		_, err = Credentials(c)
		if (expiry < time.Now().Unix()) != (err != nil) {
			t.Fatalf("expiry diagnostic: %v", err)
		}
		if err != nil && strings.Contains(err.Error(), token) {
			t.Fatal("credential leaked in diagnostic")
		}
	}
	link := filepath.Join(root, "linked-token")
	if err := os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	if _, err := Credentials(&Config{TokenFile: link}); err == nil {
		t.Fatal("symlinked credential accepted")
	}
}

func TestHostRuntimeConfiguredCredentialRootSurvivesRestart(t *testing.T) {
	root := t.TempDir()
	wrong := t.TempDir()
	t.Setenv("TUNN_CONFIG_DIR", wrong)
	c := &Config{CredentialsDir: root}
	if err := os.WriteFile(filepath.Join(root, "token"), []byte("same-publisher"), 0600); err != nil {
		t.Fatal(err)
	}
	if got, err := Credentials(c); err != nil || got != "same-publisher" {
		t.Fatal("service inherited a different credential root", err)
	}
	base, err := credentialsDirectory(c)
	if err != nil || base != root {
		t.Fatal("manifest did not pin the credential root", err)
	}
	path, err := endpointTokenIn(base, "stable-name")
	if err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		if _, err := endpointTokenIn(base, "stable-name"); err != nil {
			t.Fatal(err)
		}
		if after, _ := os.ReadFile(path); !bytes.Equal(before, after) {
			t.Fatal("restart generated a replacement capability")
		}
	}
	if _, err := os.Stat(filepath.Join(wrong, "endpoints")); !os.IsNotExist(err) {
		t.Fatal("ambient credential directory was used")
	}
	if err := os.Chmod(path, 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := endpointTokenIn(base, "stable-name"); err == nil {
		t.Fatal("readable endpoint credential was accepted or replaced")
	}
	if after, _ := os.ReadFile(path); !bytes.Equal(before, after) {
		t.Fatal("permission failure replaced the prior capability")
	}
}
