package host

import (
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/ehrlich-b/tunn/internal/downloads"
)

func TestMirrorPublicRoutesAndSharedInstaller(t *testing.T) {
	root := t.TempDir()
	t.Setenv("TUNN_DOWNLOAD_DIR", root)
	t.Setenv("TUNN_DOWNLOAD_BASE", "")
	body := `{"tag_name":"v0.1.3"}`
	if err := os.WriteFile(filepath.Join(root, "latest.json"), []byte(body), 0644); err != nil {
		t.Fatal(err)
	}
	proxy := &ProxyServer{Domain: "tunn.to"}
	handler := proxy.createHandler()
	for _, tc := range []struct {
		method, path, body string
		status             int
	}{
		{"GET", "/dl/latest.json", body, 200},
		{"POST", "/dl/latest.json", "", 405},
		{"GET", "/dl/", "", 404},
		{"GET", "/install.sh", downloads.Installer(), 200},
	} {
		request := httptest.NewRequest(tc.method, "https://tunn.to"+tc.path, nil)
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		if response.Code != tc.status || tc.body != "" && response.Body.String() != tc.body {
			t.Fatalf("%s %s: status=%d body=%q", tc.method, tc.path, response.Code, response.Body.String())
		}
	}
}
