package host

import (
	"os"
	"path/filepath"
	"regexp"
	"testing"

	"github.com/ehrlich-b/tunn/internal/config"
)

func TestGoogleDeploymentDocsMatchCallbackURI(t *testing.T) {
	p := &ProxyServer{config: &config.Config{PublicAddr: "tunn.to:443"}}
	callback := regexp.MustCompile("https://[^\\s`]+/auth/google/callback")
	for _, path := range []string{"DEPLOY.md", "DEPLOY-RUNBOOK.md", "RELEASE-NOTES.md"} {
		t.Run(path, func(t *testing.T) {
			content, err := os.ReadFile(filepath.Join("..", "..", path))
			if err != nil {
				t.Fatal(err)
			}
			uris := callback.FindAllString(string(content), -1)
			if len(uris) == 0 {
				t.Fatal("missing Google callback registration URI")
			}
			for _, uri := range uris {
				if want := p.googleCallbackURL(); uri != want {
					t.Errorf("documented Google callback = %q, authorization/token callback = %q", uri, want)
				}
			}
		})
	}
}
