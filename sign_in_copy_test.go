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
