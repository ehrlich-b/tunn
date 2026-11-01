package main

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func stageFixture(t *testing.T, root string) {
	t.Helper()
	tag := "v42.3.7"
	dir := filepath.Join(root, "downloads", tag)
	if err := os.MkdirAll(dir, 0755); err != nil {
		t.Fatal(err)
	}
	var sums strings.Builder
	assets := []map[string]string{}
	for _, name := range []string{"tunn-linux-amd64", "tunn-linux-arm64", "tunn-darwin-amd64", "tunn-darwin-arm64"} {
		data := []byte("fixture " + name)
		if err := os.WriteFile(filepath.Join(dir, name), data, 0644); err != nil {
			t.Fatal(err)
		}
		fmt.Fprintf(&sums, "%x *%s\n", sha256.Sum256(data), name)
		assets = append(assets, map[string]string{"name": name, "browser_download_url": "https://tunn.to/dl/" + tag + "/" + name})
	}
	if err := os.WriteFile(filepath.Join(dir, "SHA256SUMS"), []byte(sums.String()), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "checksums.txt"), []byte(sums.String()), 0644); err != nil {
		t.Fatal(err)
	}
	assets = append(assets, map[string]string{"name": "SHA256SUMS", "browser_download_url": "https://tunn.to/dl/" + tag + "/SHA256SUMS"})
	assets = append(assets, map[string]string{"name": "checksums.txt", "browser_download_url": "https://tunn.to/dl/" + tag + "/checksums.txt"})
	feed, _ := json.Marshal(map[string]any{"tag_name": tag, "draft": false, "prerelease": false, "assets": assets})
	if err := os.WriteFile(filepath.Join(root, "downloads/latest.json"), feed, 0644); err != nil {
		t.Fatal(err)
	}
}

func buildChecker(t *testing.T) (string, string) {
	t.Helper()
	repo, err := os.Getwd()
	if err != nil {
		t.Fatalf("working directory: %v", err)
	}
	for {
		if _, err := os.Stat(filepath.Join(repo, "go.mod")); err == nil {
			break
		} else if !os.IsNotExist(err) {
			t.Fatalf("find go.mod: %v", err)
		}
		parent := filepath.Dir(repo)
		if parent == repo {
			t.Fatal("could not find go.mod in parent directories")
		}
		repo = parent
	}
	checker := filepath.Join(t.TempDir(), "checker")
	build := exec.Command("nice", "-n", "10", "go", "build", "-p", "2", "-o", checker, "./cmd/check-downloads")
	build.Dir = repo
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build: %v\n%s", err, output)
	}
	return checker, repo
}

func TestDeployGuardNormalEntryPoint(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("make deployment uses a Unix shell")
	}
	checker, repo := buildChecker(t)
	for _, staged := range []bool{false, true} {
		for _, parallel := range []string{"-j1", "-j2"} {
			t.Run(fmt.Sprintf("staged=%v/%s", staged, parallel), func(t *testing.T) {
				root := t.TempDir()
				makefile, err := os.ReadFile(filepath.Join(repo, "Makefile"))
				if err != nil {
					t.Fatal(err)
				}

				if err := os.WriteFile(filepath.Join(root, "Makefile"), makefile, 0644); err != nil {
					t.Fatal(err)
				}
				tools := filepath.Join(root, "tools")
				if err := os.Mkdir(tools, 0755); err != nil {
					t.Fatal(err)
				}
				shim := "#!/bin/sh\nexec '" + checker + "' downloads\n"
				if err := os.WriteFile(filepath.Join(tools, "go"), []byte(shim), 0755); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(tools, "fly"), []byte("#!/bin/sh\ntouch fly-ran\n"), 0755); err != nil {
					t.Fatal(err)
				}
				if staged {
					stageFixture(t, root)
				}
				cmd := exec.Command("make", parallel, "fly-deploy")
				cmd.Dir = root
				cmd.Env = append(os.Environ(), "PATH="+tools+":"+os.Getenv("PATH"))
				output, err := cmd.CombinedOutput()
				if staged && err != nil {
					t.Fatalf("staged deploy: %v\n%s", err, output)
				}
				if !staged && (err == nil || !strings.Contains(string(output), "stage the verified release tree with cp -R")) {
					t.Fatalf("expected actionable refusal: %v\n%s", err, output)
				}
				for _, marker := range []string{"fly-ran"} {
					_, err := os.Stat(filepath.Join(root, marker))
					if staged && err != nil || !staged && !os.IsNotExist(err) {
						t.Fatalf("%s staged=%v: %v", marker, staged, err)
					}
				}
			})
		}
	}
}

func TestDeployGuardImageAndSelfHostConfig(t *testing.T) {
	checker, repo := buildChecker(t)
	dockerfile, err := os.ReadFile(filepath.Join(repo, "Dockerfile"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(dockerfile), "ARG REQUIRE_DOWNLOADS=0") {
		t.Fatal("plain docker build must default to self-host mode")
	}
	var guard string
	for _, line := range strings.Split(string(dockerfile), "\n") {
		if strings.HasPrefix(line, "RUN if [ \"$REQUIRE_DOWNLOADS\"") {
			guard = strings.TrimPrefix(line, "RUN ")
		}
	}
	if guard == "" {
		t.Fatal("missing Dockerfile production guard")
	}
	for _, tc := range []struct {
		name, config     string
		required, staged bool
	}{
		{"plain-docker", "", false, false},
		{"self-host-fly", "fly.toml.dist", false, false},
		{"production-build-missing", "", true, false},
		{"production-build-staged", "", true, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if tc.config != "" {
				config, err := os.ReadFile(filepath.Join(repo, tc.config))
				if err != nil {
					t.Fatal(err)
				}
				if strings.Contains(string(config), "REQUIRE_DOWNLOADS = \"1\"") != tc.required {
					t.Fatal("Fly build argument disagrees with deployment mode")
				}
			}
			root := t.TempDir()
			if tc.staged {
				stageFixture(t, root)
			}
			command := strings.Replace(guard, "nice -n 10 go run -p 2 ./cmd/check-downloads", "'"+checker+"'", 1)
			cmd := exec.Command("sh", "-c", command)
			cmd.Dir = root
			required := "0"
			if tc.required {
				required = "1"
			}
			cmd.Env = append(os.Environ(), "REQUIRE_DOWNLOADS="+required)
			output, err := cmd.CombinedOutput()
			if tc.required && !tc.staged {
				if err == nil || !strings.Contains(string(output), "Deployment refused") {
					t.Fatalf("expected production refusal: %v\n%s", err, output)
				}
			} else if err != nil {
				t.Fatalf("image guard: %v\n%s", err, output)
			}
		})
	}
}
