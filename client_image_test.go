package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// Exercise the shell that supplies the publish action's coordinates; malformed
// GITHUB_OUTPUT lines can otherwise survive all Go and Docker build checks.
func TestStatusClientImageManualWorkflow(t *testing.T) {
	data, err := os.ReadFile(".github/workflows/client-image.yml")
	if err != nil {
		t.Fatal(err)
	}
	var workflow struct {
		On   map[string]any `yaml:"on"`
		Jobs map[string]struct {
			Needs       string            `yaml:"needs"`
			Environment string            `yaml:"environment"`
			Permissions map[string]string `yaml:"permissions"`
			Steps       []struct {
				Name string            `yaml:"name"`
				Run  string            `yaml:"run"`
				Uses string            `yaml:"uses"`
				With map[string]string `yaml:"with"`
			} `yaml:"steps"`
		} `yaml:"jobs"`
	}
	if err = yaml.Unmarshal(data, &workflow); err != nil {
		t.Fatal(err)
	}
	if len(workflow.On) != 1 {
		t.Fatal("unexpected automatic publication trigger")
	}
	if _, ok := workflow.On["workflow_dispatch"]; !ok {
		t.Fatal("manual trigger missing")
	}
	publish := workflow.Jobs["publish"]
	if publish.Needs != "verify" || publish.Environment != "client-image-release" || publish.Permissions["packages"] != "write" {
		t.Fatal("publication gates missing")
	}
	var coordinates, build bool
	for _, step := range publish.Steps {
		if step.Name == "Image coordinates" {
			coordinates = true
			output := filepath.Join(t.TempDir(), "output")
			cmd := exec.Command("bash", "-eu", "-c", step.Run)
			cmd.Env = []string{"PATH=" + os.Getenv("PATH"), "GITHUB_REPOSITORY=Fixture/Tunn", "GITHUB_SHA=" + strings.Repeat("a", 40), "GITHUB_OUTPUT=" + output}
			if b, err := cmd.CombinedOutput(); err != nil {
				t.Fatal(err, string(b))
			}
			b, err := os.ReadFile(output)
			if err != nil || string(b) != "name=ghcr.io/fixture/tunn-client\ntag=sha-"+strings.Repeat("a", 40)+"\n" {
				t.Fatal("invalid publication coordinates", string(b), err)
			}
		}
		if strings.HasPrefix(step.Uses, "docker/build-push-action@") {
			build = true
			if step.With["platforms"] != "linux/amd64,linux/arm64" || step.With["file"] != "Dockerfile.client" || step.With["provenance"] != "mode=max" || step.With["sbom"] != "true" {
				t.Fatal("multiarch publication missing", step.With)
			}
		}
	}
	if !coordinates || !build {
		t.Fatal("publication steps missing")
	}
	var gates bool
	for _, step := range workflow.Jobs["verify"].Steps {
		if step.Run == "make check && make vet && git diff --exit-code" {
			gates = true
		}
	}
	if !gates {
		t.Fatal("repository gates missing")
	}
}

func TestStatusClientImageQuickstartRemainsPrivate(t *testing.T) {
	// Parse the actual application targets used in the copyable Docker commands.
	for _, target := range []string{"8080", "http://host.docker.internal:8080"} {
		o, err := parseServeFlags([]string{target})
		if err != nil || o.public || len(o.allowedEmails) != 0 || o.bearer {
			t.Fatal("quickstart changed access defaults", o, err)
		}
	}
	o, err := parseServeFlags([]string{"8080", "--allow=friend@example.com"})
	if err != nil || o.public || len(o.allowedEmails) != 1 {
		t.Fatal(o, err)
	}
	o, err = parseServeFlags([]string{"8080", "--public"})
	if err != nil || !o.public {
		t.Fatal(o, err)
	}
}
