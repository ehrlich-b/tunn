package main

import (
	"bytes"
	"context"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	pb "github.com/ehrlich-b/tunn/pkg/proto/tunnelv1"
	"github.com/golang-jwt/jwt/v4"
	"google.golang.org/grpc"
)

// Re-exec the actual command dispatcher in an isolated home against a TLS
// loopback relay. Never uses the developer's login or endpoint credentials.
func TestConnectorPublisherCLIHelper(t *testing.T) {
	if os.Getenv("TUNN_CONNECTOR_CLI_HELPER") != "1" {
		return
	}
	os.Args = []string{"tunn", "mcp", "--name", "cli-tools", "--secret", os.Getenv("TUNN_FIXTURE_JWT"), "--tools", "echo", "--", "python3", "examples/mcp/echo.py"}
	main()
	os.Exit(0)
}

type connectorPublisherRelay struct {
	pb.UnimplementedTunnelServiceServer
	result chan error
}

func (s *connectorPublisherRelay) EstablishTunnel(stream grpc.BidiStreamingServer[pb.TunnelMessage, pb.TunnelMessage]) (err error) {
	defer func() { s.result <- err }()
	message, err := stream.Recv()
	if err != nil {
		return err
	}
	registration := message.GetRegisterClient()
	if registration == nil || registration.TunnelId != "cli-tools" || registration.ExposureMode == "public" || registration.TargetUrl != "mcp" || len(registration.AccessTokenSha256) != 32 || len(registration.AllowedEmails) != 1 || registration.AllowedEmails[0] != "owner@example.com" {
		return fmt.Errorf("private MCP registration contract failed")
	}
	err = stream.Send(&pb.TunnelMessage{Message: &pb.TunnelMessage_RegisterResponse{RegisterResponse: &pb.RegisterResponse{Success: true, PublicUrl: "https://cli-tools.tunn.test"}}})
	if err != nil {
		return err
	}
	bodies := []string{
		`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"fixture","version":"1"}}}`,
		`{"jsonrpc":"2.0","method":"notifications/initialized"}`,
		`{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}`,
		`{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"echo","arguments":{"message":"hello"}}}`,
		`{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"hidden_echo","arguments":{}}}`,
	}
	session := ""
	for index, body := range bodies {
		id := fmt.Sprint(index)
		headers := map[string]string{"Content-Type": "application/json", "Accept": "application/json, text/event-stream"}
		if session != "" {
			headers["Mcp-Session-Id"] = session
			headers["Mcp-Protocol-Version"] = "2025-11-25"
		}
		err = stream.Send(&pb.TunnelMessage{Message: &pb.TunnelMessage_HttpRequest{HttpRequest: &pb.HttpRequest{ConnectionId: id, Method: "POST", Path: "/mcp", Headers: headers, Body: []byte(body)}}})
		if err != nil {
			return err
		}
		var response *pb.HttpResponse
		for response == nil {
			message, err = stream.Recv()
			if err != nil {
				return err
			}
			response = message.GetHttpResponse()
		}
		if response.ConnectionId != id {
			return fmt.Errorf("request correlation failed")
		}
		if index == 1 {
			if response.StatusCode != 202 && response.StatusCode != 204 {
				return fmt.Errorf("initialized notification failed")
			}
			continue
		}
		if response.StatusCode != 200 {
			return fmt.Errorf("MCP POST failed: %d", response.StatusCode)
		}
		var rpc struct {
			Result json.RawMessage
			Error  *struct{ Code int }
		}
		if json.Unmarshal(response.Body, &rpc) != nil {
			return fmt.Errorf("invalid response")
		}
		switch index {
		case 0:
			for key, value := range response.Headers {
				if strings.EqualFold(key, "Mcp-Session-Id") {
					session = value
				}
			}
			if !bytes.Contains(rpc.Result, []byte("tunn-echo-demo")) {
				return fmt.Errorf("initialize failed")
			}
		case 2:
			var list struct{ Tools []struct{ Name string } }
			if json.Unmarshal(rpc.Result, &list) != nil || len(list.Tools) != 1 || list.Tools[0].Name != "echo" {
				return fmt.Errorf("filtered list failed")
			}
		case 3:
			if rpc.Error != nil || !bytes.Contains(rpc.Result, []byte(`"hello"`)) {
				return fmt.Errorf("echo call failed")
			}
		case 4:
			if rpc.Error == nil || rpc.Error.Code != -32001 {
				return fmt.Errorf("blocked call failed")
			}
		}
	}
	// Leave the control stream connected until the CLI's signal shutdown.
	s.result <- nil
	<-stream.Context().Done()
	return nil
}
func TestConnectorPublisherCLI(t *testing.T) {
	if _, err := exec.LookPath("python3"); err != nil {
		t.Fatal("fixture requires python3")
	}
	relay := &connectorPublisherRelay{result: make(chan error, 2)}
	gs := grpc.NewServer()
	pb.RegisterTunnelServiceServer(gs, relay)
	server := httptest.NewUnstartedServer(gs)
	server.EnableHTTP2 = true
	server.StartTLS()
	defer server.Close()
	defer gs.Stop()
	root := t.TempDir()
	ca := filepath.Join(root, "fixture-ca.pem")
	if err := os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw}), 0600); err != nil {
		t.Fatal(err)
	}
	token, err := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{"email": "owner@example.com"}).SignedString([]byte("disposable-fixture"))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestConnectorPublisherCLIHelper$")
	command.Env = []string{"PATH=" + os.Getenv("PATH"), "HOME=" + root, "TUNN_ENV=prod", "TUNN_SERVER_ADDR=" + strings.TrimPrefix(server.URL, "https://"), "SSL_CERT_FILE=" + ca, "TUNN_CONNECTOR_CLI_HELPER=1", "TUNN_FIXTURE_JWT=" + token}
	var output bytes.Buffer
	command.Stdout = &output
	command.Stderr = &output
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	waited := make(chan error, 1)
	go func() { waited <- command.Wait() }()
	t.Cleanup(func() {
		cancel()
		select {
		case <-waited:
		case <-time.After(5 * time.Second):
			t.Error("fixture CLI did not exit")
		}
	})
	select {
	case err := <-relay.result:
		if err != nil {
			t.Fatal(err)
		}
	case <-ctx.Done():
		t.Fatal("CLI failed to publish and serve fixture before deadline")
	}
	if err := command.Process.Signal(syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-waited:
		// Put the exit result back for cleanup; only read output after Wait.
		waited <- err
		if err != nil {
			t.Fatal("CLI signal shutdown failed")
		}
	case <-ctx.Done():
		t.Fatal("CLI signal shutdown timed out")
	}
	text := output.String()
	for _, want := range []string{"Connector URL: https://cli-tools.tunn.test/mcp", "Check connection: tunn connector-check --oauth https://cli-tools.tunn.test/mcp"} {
		if !strings.Contains(text, want) {
			t.Errorf("CLI missing publication instruction %q", want)
		}
	}
	if strings.Contains(text, token) {
		t.Fatal("publisher credential printed")
	}
	t.Log("PASS actual tunn mcp dispatcher, private TLS registration, echo initialize/list/call/denial and signal shutdown")
}
