package main

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

func opsScriptEnvironment(extra ...string) []string {
	var result []string
	for _, item := range os.Environ() {
		key, _, _ := strings.Cut(item, "=")
		if !strings.HasPrefix(key, "TUNN_") && !strings.HasPrefix(key, "OPS_") {
			result = append(result, item)
		}
	}
	return append(result, extra...)
}

func TestOpsDockerEntrypointCertificateFixtures(t *testing.T) {
	source, err := os.ReadFile("scripts/docker-entrypoint.sh")
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name, cert, key string
		mounted, valid  bool
	}{
		{"decoded pair", base64.StdEncoding.EncodeToString([]byte("fixture certificate")), base64.StdEncoding.EncodeToString([]byte("fixture private key")), false, true},
		{"mounted pair", "", "", true, true},
		{"missing files", "", "", false, false},
		{"certificate only", "Y2VydA==", "", false, false},
		{"private key only", "", "a2V5", false, false},
		{"bad certificate encoding", "!!invalid!!", "a2V5", true, false},
		{"bad key encoding", "Y2VydA==", "!!invalid!!", true, false},
		{"empty decoded certificate", "\n", "a2V5", false, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			root := t.TempDir()
			binary := filepath.Join(root, "tunn")
			receipt := filepath.Join(root, "receipt")
			if err := os.WriteFile(binary, []byte("#!/bin/sh\nprintf '%s\\n' \"$$\" \"$1\" \"$TUNN_CERT_FILE\" \"$TUNN_KEY_FILE\" > \"$OPS_RECEIPT\"\n"), 0700); err != nil {
				t.Fatal(err)
			}
			script := filepath.Join(root, "start.sh")
			if err := os.WriteFile(script, []byte(strings.ReplaceAll(string(source), "/app/tunn", binary)), 0700); err != nil {
				t.Fatal(err)
			}
			certPath, keyPath := filepath.Join(root, "cert.pem"), filepath.Join(root, "key.pem")
			if test.mounted {
				for _, path := range []string{certPath, keyPath} {
					if err := os.WriteFile(path, []byte("retained fixture"), 0600); err != nil {
						t.Fatal(err)
					}
				}
			}
			cmd := exec.Command("sh", script)
			cmd.Env = opsScriptEnvironment("TUNN_CERT_FILE="+certPath, "TUNN_KEY_FILE="+keyPath, "TUNN_CERT_DATA="+test.cert, "TUNN_KEY_DATA="+test.key, "OPS_RECEIPT="+receipt)
			output, runErr := cmd.CombinedOutput()
			if test.valid {
				if runErr != nil {
					t.Fatalf("valid startup failed: %v %s", runErr, output)
				}
				data, err := os.ReadFile(receipt)
				if err != nil {
					t.Fatal(err)
				}
				lines := strings.Split(strings.TrimSpace(string(data)), "\n")
				if len(lines) != 4 || lines[0] != strconv.Itoa(cmd.Process.Pid) || lines[1] != "-mode=host" || lines[2] != certPath || lines[3] != keyPath {
					t.Fatal("entrypoint did not exec the host with configured paths")
				}
				for _, path := range []string{certPath, keyPath} {
					info, err := os.Stat(path)
					if err != nil || info.Mode().Perm()&0077 != 0 {
						t.Fatal("certificate material was not private")
					}
				}
				if !test.mounted {
					data, err := os.ReadFile(keyPath)
					if err != nil || string(data) != "fixture private key" {
						t.Fatal("private key decoding changed contents")
					}
				}
			} else {
				if runErr == nil {
					t.Fatal("invalid TLS input launched host")
				}
				if _, err := os.Stat(receipt); !os.IsNotExist(err) {
					t.Fatal("failed startup executed host")
				}
				if test.mounted {
					for _, path := range []string{certPath, keyPath} {
						data, err := os.ReadFile(path)
						if err != nil || string(data) != "retained fixture" {
							t.Fatal("decode failure replaced mounted material")
						}
					}
				}
			}
			files, err := filepath.Glob(filepath.Join(root, "*.tmp.*"))
			if err != nil || len(files) != 0 {
				t.Fatal("startup left temporary credential files")
			}
		})
	}
}

const opsFakeCurl = `#!/usr/bin/env python3
import json, os, sys
from urllib.parse import urlsplit
args=sys.argv[1:]
assert args[0]=='--disable', args
assert '--insecure' not in args and '-k' not in args and '--location' not in args
assert args[args.index('--proto')+1]=='=https'
assert args[args.index('--connect-timeout')+1]=='5'
assert args[args.index('--max-time')+1]=='15'
method='HEAD' if '--head' in args else args[args.index('--request')+1]
assert method in ('GET','HEAD')
path=urlsplit(args[-1]).path
assert path in ('/health','/readyz','/','/install.sh')
with open(os.environ['OPS_CURL_LOG'],'a') as f: f.write(json.dumps({'method':method,'path':path,'args':args})+chr(10))
mode=os.environ.get('OPS_CURL_MODE','success')
version='3' if '--http3-only' in args else '2' if '--http2' in args else '1.1'
status='200'
body='ok' if path in ('/health','/readyz') else 'fixture read-only response'
if mode=='tls': sys.exit(60)
if mode=='http3 unsupported' and version=='3': sys.exit(2)
if mode=='fallback' and version=='2': version='1.1'
if mode=='unready' and path=='/readyz': status='503'
if mode=='redirect' and path=='/': status='302'
if mode=='wrong body' and path=='/health': body='unexpected'
with open(args[args.index('--output')+1],'w') as f: f.write(body)
sys.stdout.write(status+' '+version)
`

func opsSmokeFixture(t *testing.T, mode string, args ...string) ([]map[string]any, []byte, error) {
	t.Helper()
	root := t.TempDir()
	logPath := filepath.Join(root, "curl.jsonl")
	if err := os.WriteFile(filepath.Join(root, "curl"), []byte(opsFakeCurl), 0700); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("sh", append([]string{"scripts/smoke-prod.sh"}, args...)...)
	cmd.Env = opsScriptEnvironment("PATH="+root+string(os.PathListSeparator)+os.Getenv("PATH"), "OPS_CURL_MODE="+mode, "OPS_CURL_LOG="+logPath, "TMPDIR="+root)
	output, err := cmd.CombinedOutput()
	log, _ := os.ReadFile(logPath)
	var calls []map[string]any
	for _, line := range strings.Split(strings.TrimSpace(string(log)), "\n") {
		if line == "" {
			continue
		}
		var call map[string]any
		if err := json.Unmarshal([]byte(line), &call); err != nil {
			t.Fatal(err)
		}
		calls = append(calls, call)
	}
	files, globErr := filepath.Glob(filepath.Join(root, "tunn-smoke.*"))
	if globErr != nil || len(files) != 0 {
		t.Fatal("smoke left temporary response files")
	}
	return calls, output, err
}

func TestOpsSmokeReadOnlyProtocolChecks(t *testing.T) {
	for _, h3 := range []bool{false, true} {
		args := []string{"https://tunn.test/"}
		want := 8
		if h3 {
			args = append(args, "--http3")
			want = 10
		}
		calls, output, err := opsSmokeFixture(t, "success", args...)
		if err != nil || len(calls) != want || strings.Count(string(output), "PASS ") != want {
			t.Fatalf("smoke success: %v %s calls=%d", err, output, len(calls))
		}
		for _, call := range calls {
			if call["method"] != "GET" && call["method"] != "HEAD" {
				t.Fatal("smoke issued a write")
			}
		}
	}
}

func TestOpsSmokeFailsOnDeploymentOrProtocolErrors(t *testing.T) {
	for _, mode := range []string{"tls", "fallback", "unready", "redirect", "wrong body", "http3 unsupported"} {
		t.Run(mode, func(t *testing.T) {
			_, output, err := opsSmokeFixture(t, mode, "https://tunn.test", "--http3")
			if err == nil || !strings.Contains(string(output), "FAIL") {
				t.Fatalf("deployment error passed: %v %s", err, output)
			}
		})
	}
}

func TestOpsSmokeRejectsInvalidOriginsWithoutRequests(t *testing.T) {
	for _, args := range [][]string{nil, {"http://tunn.test"}, {"https://user:fixture-secret@tunn.test"}, {"https://tunn.test/prefix"}, {"https://tunn.test?query"}, {"https://tunn.test/#fragment"}, {"https://tunn.test:0"}, {"https://tunn.test\n"}, {"https://tunn.test", "--write"}} {
		calls, output, err := opsSmokeFixture(t, "success", args...)
		if err == nil || len(calls) != 0 || strings.Contains(string(output), "fixture-secret") {
			t.Fatalf("invalid origin was accepted or echoed: %v %s", err, output)
		}
	}
}

func TestOpsDockerBuildAndFlyPersistenceContract(t *testing.T) {
	docker, err := os.ReadFile("Dockerfile")
	if err != nil {
		t.Fatal(err)
	}
	module, err := os.ReadFile("go.mod")
	if err != nil {
		t.Fatal(err)
	}
	image := regexp.MustCompile(`golang:(\d+)\.(\d+)`).FindStringSubmatch(string(docker))
	minimum := regexp.MustCompile(`(?m)^go (\d+)\.(\d+)`).FindStringSubmatch(string(module))
	if len(image) != 3 || len(minimum) != 3 {
		t.Fatal("cannot verify compiler version")
	}
	major, _ := strconv.Atoi(image[1])
	minor, _ := strconv.Atoi(image[2])
	wantMajor, _ := strconv.Atoi(minimum[1])
	wantMinor, _ := strconv.Atoi(minimum[2])
	if major < wantMajor || major == wantMajor && minor < wantMinor {
		t.Fatal("Docker compiler predates module requirements")
	}
	for _, required := range []string{"CGO_ENABLED=0 go build", "ca-certificates", "COPY --from=builder /tunn", "COPY scripts/docker-entrypoint.sh /app/start.sh", `ENTRYPOINT ["/app/start.sh"]`} {
		if !strings.Contains(string(docker), required) {
			t.Fatalf("Docker build/runtime lost %s", required)
		}
	}
	fly, err := os.ReadFile("fly.toml.dist")
	if err != nil {
		t.Fatal(err)
	}
	for _, required := range []string{`TUNN_ENV = "prod"`, `TUNN_LOGIN_NODE = "true"`, `destination = "/data"`, `protocol = "tcp"`, `protocol = "udp"`} {
		if !strings.Contains(string(fly), required) {
			t.Fatalf("Fly deployment lost %s", required)
		}
	}
}
