package main

import (
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// Match promises in prose, including HTML metadata, wrapped lines and Markdown.
// Provider identifiers, repository URLs and webhook examples are not promises.
var githubSignInPromise = regexp.MustCompile(`(?i)\b(?:(?:sign(?:s|ing)?[ -]?in|log(?:s|ging)?[ -]?in|login)\s+(?:with|through|using)\s+github|github\s+(?:oauth\s+)?sign[ -]?in|(?:choose|chooses|select|use|continue\s+with)\s+github|one[ -]time\s+github\s+auth|existing\s+github\s+or\s+email\s+flow|email/github\s+login)\b`)
var copyHTMLTag = regexp.MustCompile(`<[^>]*>`)

func normalizedSignInCopy(content string) string {
	content = copyHTMLTag.ReplaceAllStringFunc(content, func(tag string) string {
		if strings.HasPrefix(strings.ToLower(tag), "<meta ") {
			return tag // Search and social descriptions are user-facing copy too.
		}
		return " "
	})
	content = strings.NewReplacer("*", "", "`", "").Replace(content)
	return strings.Join(strings.Fields(content), " ")
}

func TestPublicCopyUsesConfiguredSignIn(t *testing.T) {
	paths := []string{"README.md", "USER-JOURNEY.md"}
	for _, root := range []string{"docs", "internal/host/templates"} {
		err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if entry.IsDir() {
				return nil
			}
			// Legal copy requires a separate review and is outside this copy gate.
			if path == "internal/host/templates/terms.html" || path == "internal/host/templates/privacy.html" {
				return nil
			}
			if filepath.Ext(path) == ".md" || filepath.Ext(path) == ".html" {
				paths = append(paths, path)
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	// CLI usage text lives in main.go and the command-specific source files.
	cliPaths, err := filepath.Glob("*_cli.go")
	if err != nil {
		t.Fatal(err)
	}
	paths = append(paths, "main.go")
	paths = append(paths, cliPaths...)
	for _, path := range paths {
		t.Run(path, func(t *testing.T) {
			content, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if promise := githubSignInPromise.FindString(normalizedSignInCopy(string(content))); promise != "" {
				t.Errorf("copy promises GitHub sign-in (%q); describe the methods offered by the relay", promise)
			}
		})
	}
}

func TestGitHubSignInPromiseDetection(t *testing.T) {
	for _, copy := range []string{
		"Alex signs in with GitHub\nor an email link.",
		`<meta name="description" content="HTTPS tunnel with GitHub OAuth sign-in and an email allow-list.">`,
		"Select **Continue with GitHub** or **Continue with Email**.",
		"Use GitHub or a magic link.",
		"tunn login # One-time GitHub auth",
	} {
		if !githubSignInPromise.MatchString(normalizedSignInCopy(copy)) {
			t.Errorf("missed sign-in promise: %q", copy)
		}
	}
}

// Email grants and wildcard app handoffs require personal identities, even
// when the relay also offers company login. Scope this check to those flows;
// company/group sharing has separate, valid instructions in README and org-sso.
func TestPersonalAccessCopy(t *testing.T) {
	personalIdentity := regexp.MustCompile(`(?i)\bpersonal(?: tunn)? account\b|\bpersonal sign-in\b`)
	companyIdentity := regexp.MustCompile(`(?i)\b(?:company|corporate|org(?:anization)?)\b`)
	for _, section := range []struct {
		path, start, end string
	}{
		{"README.md", "Share a local app privately", "Relays can also offer"},
		{"USER-JOURNEY.md", "7. ", "Next app:"},
		{"DESIGN.md", "# Wildcard app authorization", "\nApp ingress"},
		{"docs/APPS-DOMAINS.md", "Wildcard app ingress", "## App-name capacity"},
		{"docs/APPS-DOMAINS.md", "Use the login authority", "Google OAuth"},
		{"docs/guides/openclaw.md", "3. **Open the printed HTTPS URL", "\nTLS terminates"},
		{"docs/guides/tunn-and-tailscale.md", "Replace the email", "## Share a home server"},
		{"docs/ssh-api.md", "The session prints the HTTPS URL", "Ctrl-C"},
		{"internal/host/templates/docs.html", "Send them the printed HTTPS URL", "</p>"},
		{"internal/host/templates/homepage.html", "Alex signs in", "</p>"},
		{"internal/host/templates/share-dev-server-oauth.html", "<h2>What happens", "<h2>Allow several"},
	} {
		t.Run(section.path+"/"+section.start, func(t *testing.T) {
			content, err := os.ReadFile(section.path)
			if err != nil {
				t.Fatal(err)
			}
			_, body, ok := strings.Cut(string(content), section.start)
			if !ok {
				t.Fatal("personal access instructions not found; update the copy guard's section boundary")
			}
			body, _, ok = strings.Cut(body, section.end)
			if !ok {
				t.Fatal("personal access instructions have no end; update the copy guard's section boundary")
			}
			copy := normalizedSignInCopy(body)
			if !personalIdentity.MatchString(copy) {
				t.Error("email-grant and wildcard-app instructions must specify a personal account or personal sign-in")
			}
			if companyIdentity.MatchString(copy) {
				t.Error("keep company/group sign-in instructions in their corresponding access flow")
			}
		})
	}
}
