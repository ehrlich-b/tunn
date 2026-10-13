package main

import (
	"bytes"
	"errors"
	"github.com/ehrlich-b/tunn/internal/common"
	"strings"
	"testing"
	"time"
)

func TestCLIInventoryDoesNotInferAppHealth(t *testing.T) {
	var out, errout bytes.Buffer
	machines := []common.Machine{{Name: "laptop", Tunnels: []common.HostEndpoint{{Name: "app", Kind: "http", URL: "https://app.example", Online: true, LastSeen: time.Now()}}}}
	if err := printHosts(&out, &errout, machines); err != nil {
		t.Fatal(err)
	}
	for _, text := range []string{"Edge connected", "App not checked", "tunn access app"} {
		if !strings.Contains(out.String(), text) {
			t.Fatal(out.String())
		}
	}
	if strings.Contains(out.String(), "Online") || strings.Contains(out.String(), "[ok]") {
		t.Fatal("invented app health")
	}
}
func TestCLIServiceFailureRetainsRecovery(t *testing.T) {
	var out, errout bytes.Buffer
	err := serviceStatusResult(&out, "Service not installed", errors.New("manager query failed"))
	writeHostError(&errout, &errout, err, nil)
	if !strings.Contains(errout.String(), "Service not installed") || !strings.Contains(errout.String(), "tunn service --help") {
		t.Fatal(errout.String())
	}
	out.Reset()
	if err := serviceStatusResult(&out, "service is not running", nil); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out.String(), "[i] Service running") {
		t.Fatal("substring created a false status")
	}
}
