package main

import (
	"html"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// Check vocabulary rather than enumerating the promises removed from the copy.
// Twelve intervening words allow provider lists and ordinary sentence variations.
var copyHTMLTag = regexp.MustCompile(`<[^>]*>`)
var copyHTMLComment = regexp.MustCompile(`(?s)<!--.*?-->`)
var copyMetaContent = regexp.MustCompile(`(?i)\bcontent\s*=\s*(?:"([^"]*)"|'([^']*)')`)
var copyBlockTag = regexp.MustCompile(`(?i)^</?(?:p|div|h[1-6]|li|pre|title|section|article|br|meta)\b`)
var copySentenceEnd = regexp.MustCompile(`[.!?](?:\s+|$)|\n\s*\n`)
var copyImplementationBlock = regexp.MustCompile("(?ms)^```(?:python|go|json)[^\n]*\n.*?^```[^\n]*$")
var copyCLIOption = regexp.MustCompile(`(?m)^([ \t]*--[a-z])`)
var copyMarkdownLink = regexp.MustCompile(`\[([^\]]+)\]\([^)]*\)`)
var copyWord = regexp.MustCompile(`[\pL\pN_]+`)
var copyGitHubURL = regexp.MustCompile(`(?i)\b(?:[a-z0-9-]+\.)*github\.com\b[^\s)"'<>]*`)

func normalizedSignInCopy(content string) string {
	return strings.Join(strings.Fields(strings.NewReplacer("*", "", "`", "").Replace(
		html.UnescapeString(copyHTMLTag.ReplaceAllString(content, " ")))), " ")
}

func signInCopySentences(content string) []string {
	content = copyImplementationBlock.ReplaceAllString(content, "\n\n")
	content = copyCLIOption.ReplaceAllString(content, "\n$1")
	content = copyMarkdownLink.ReplaceAllString(content, "$1")
	content = copyHTMLComment.ReplaceAllString(content, " ")
	content = copyHTMLTag.ReplaceAllStringFunc(content, func(tag string) string {
		if strings.HasPrefix(strings.ToLower(tag), "<meta ") {
			if value := copyMetaContent.FindStringSubmatch(tag); value != nil {
				return "\n\n" + value[1] + value[2] + "\n\n"
			}
		}
		if copyBlockTag.MatchString(tag) {
			return "\n\n"
		}
		return " "
	})
	content = html.UnescapeString(content)
	var sentences []string
	start := 0
	for _, end := range copySentenceEnd.FindAllStringIndex(content, -1) {
		if sentence := normalizedSignInCopy(content[start:end[1]]); sentence != "" {
			sentences = append(sentences, sentence)
		}
		start = end[1]
	}
	if sentence := normalizedSignInCopy(content[start:]); sentence != "" {
		sentences = append(sentences, sentence)
	}
	return sentences
}

func hasGitHubSignInVocabulary(sentence string) bool {
	words := copyWord.FindAllString(strings.ToLower(copyGitHubURL.ReplaceAllString(sentence, " ")), -1)
	for i, word := range words {
		if word != "github" {
			continue
		}
		for j, candidate := range words {
			size := 1
			vocabulary := false
			switch candidate {
			case "login", "oauth", "auth", "authenticate", "authenticates", "authenticated", "authentication", "provider", "providers", "account", "accounts":
				vocabulary = true
			case "sign", "signs", "signed", "signing", "log", "logs", "logged", "logging":
				vocabulary = j+1 < len(words) && (words[j+1] == "in" || words[j+1] == "up")
				size = 2
			case "continue":
				vocabulary = j+1 < len(words) && words[j+1] == "with"
				size = 2
			case "magic":
				// The existing OpenClaw fixture says "Use GitHub or a magic link."
				vocabulary = j+1 < len(words) && words[j+1] == "link"
				size = 2
			}
			gap := j - i - 1
			if j < i {
				gap = i - (j + size)
			}
			if vocabulary && gap <= 12 {
				return true
			}
		}
	}
	return false
}

// Exceptions are exact normalized sentences, scoped to one file, so nearby new
// promises cannot inherit an exemption. Retained provider contracts describe
// existing identities, not visitor sign-in choices; legal text is frozen by the brief.
var allowedGitHubCopy = map[string]map[string]string{
	"USER-JOURNEY.md": {
		"Unverified GitHub primary emails and non-authoritative Google third-party emails fail at the provider callback.": "Retained provider validation contract for existing identities.",
	},
	"DESIGN.md": {
		"Existing linking rules remain: fresh mailbox proof joins the account containing that exact case-folded email; GitHub can join verified mailbox buckets through its verified email set, with the existing merge and suspension rules.": "Retained account-linking contract for existing identities.",
	},
	"docs/APPS-DOMAINS.md": {
		"The assertion uses EdDSA with kid, iss=https://tunn.to:443 (or configured login authority), aud= without port, canonical tunn account UUID in both sub and account_id, email, email_verified=true, provider and idp (github, magic_link, or google), iat, nbf, and a two-minute exp.": "Retained JWT provider identifiers, not offered sign-in methods.",
		"GitHub requires a verified primary email; email requires a fresh one-use magic link.": "Retained provider validation contract for existing identities.",
	},
	"docs/durable-device-design.md": {
		"At production base 110485c, browser login (GitHub or a one-use magic link) sets a seven-day HMAC JWT cookie.": "Explicit historical behavior at the named production base.",
	},
	"docs/org-sso.md": {
		"Personal /auth/google (without org) and GitHub login use signed browser state, not the organization pending-state table.": "Retained personal-provider state contract, separate from organization SSO.",
		"They are separate from personal Google/GitHub/magic-link accounts with the same display email.":                           "Existing personal-account isolation contract, not offered sign-in methods.",
	},
	"docs/webhook-verification.md": {
		"Provider references: Stripe, GitHub, Slack, Shopify.": "Repository-host webhook verification references, not sign-in providers.",
	},
	"internal/host/templates/webhook-verification.html": {
		"Provider references: Stripe · GitHub · Slack · Shopify": "Repository-host webhook verification references, not sign-in providers.",
	},
	"main.go": {
		"--verify-webhook PROVIDER Stripe, GitHub, Slack, Shopify or hmac-sha256 (lowercase)": "Repository-host webhook CLI option, not sign-in providers.",
	},
	"internal/host/templates/privacy.html": {
		"GitHub Account Info: When you log in, we get your email address(es) from GitHub.": "Existing legal sentence is frozen by the brief pending separate legal review.",
	},
	"internal/host/templates/terms.html": {
		"You need a verified email address to use tunn (via GitHub login or magic link).": "Existing legal sentence is frozen by the brief pending separate legal review.",
	},
}

func githubSignInPromises(path, content string) []string {
	var promises []string
	for _, sentence := range signInCopySentences(content) {
		if hasGitHubSignInVocabulary(sentence) && allowedGitHubCopy[path][sentence] == "" {
			promises = append(promises, sentence)
		}
	}
	return promises
}

func TestPublicCopyUsesConfiguredSignIn(t *testing.T) {
	// All eleven prose files changed by the copy work are covered, including
	// DESIGN; recursively include docs Markdown and every public HTML template.
	paths := []string{"README.md", "USER-JOURNEY.md", "DESIGN.md"}
	for _, root := range []string{"docs", "internal/host/templates"} {
		err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if !entry.IsDir() && ((root == "docs" && filepath.Ext(path) == ".md") ||
				(root == "internal/host/templates" && filepath.Ext(path) == ".html")) {
				paths = append(paths, path)
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	// Retain CLI coverage from the original guard.
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
			for _, promise := range githubSignInPromises(path, string(content)) {
				t.Errorf("copy promises GitHub sign-in (%q); describe the methods offered by the relay", promise)
			}
		})
	}
}

func TestGitHubSignInPromiseDetection(t *testing.T) {
	for _, fixture := range []struct {
		name, path, copy string
	}{
		{"wrapped sign-in", "fixture", "Alex signs in with GitHub\nor an email link."},
		{"HTML metadata", "fixture", `<meta name="description" content="HTTPS tunnel with GitHub OAuth sign-in and an email allow-list.">`},
		{"Markdown buttons", "fixture", "Select **Continue with GitHub** or **Continue with Email**."},
		{"magic link alternative", "fixture", "Use GitHub or a magic link."},
		{"CLI comment", "fixture", "tunn login # One-time GitHub auth"},
		{"M1 status-docs revert", "internal/host/templates/status-docs.html", "It doesn't check your tunnel, your app, every region or the GitHub and email sign-in providers."},
		{"M2 homepage provider list", "internal/host/templates/homepage.html", "Alex signs in to a personal account with the allowed email, using Google, GitHub or an email link where offered by the relay."},
		{"M3 Tailscale guide", "docs/guides/tunn-and-tailscale.md", "Alex signs in via GitHub, Google or an email link."},
		{"DESIGN owner revert", "DESIGN.md", "The owner signs in through GitHub (verified primary email), an email magic link,\nor Google when configured."},
		{"DESIGN account revert", "DESIGN.md", "An attacker with a different GitHub account or different mailbox gets their own\nUUID and receives 403 after login unless explicitly shared."},
		{"HTML tags and entities", "fixture", "<p>Sign <em>in</em> using Google, <strong>Git&#72;ub</strong> or email.</p>"},
		{"account variation", "fixture", "Open this app with your GitHub account."},
		{"OAuth variation", "fixture", "GitHub provides OAuth for visitors."},
		{"authenticate variation", "fixture", "Authenticate through GitHub."},
		{"login variation", "fixture", "GitHub login opens the app."},
		{"provider variation", "fixture", "Our provider choices include Google and GitHub."},
		{"log in variation", "fixture", "Log in via GitHub."},
		{"hyphenated variation", "fixture", "GitHub sign-in opens the app."},
		{"twelve words before GitHub", "fixture", "Sign in " + strings.Repeat("word ", 12) + "GitHub."},
		{"twelve words after GitHub", "fixture", "GitHub " + strings.Repeat("word ", 12) + "sign in."},
	} {
		t.Run(fixture.name, func(t *testing.T) {
			if len(githubSignInPromises(fixture.path, fixture.copy)) == 0 {
				t.Errorf("missed sign-in promise: %q", fixture.copy)
			}
		})
	}
	for _, copy := range []string{
		"Import github.com/ehrlich-b/tunn/sdk before you authenticate.",
		"Sign in with Google. Find the source on GitHub.",
		"GitHub " + strings.Repeat("word ", 13) + "sign in.",
		"Sign in " + strings.Repeat("word ", 13) + "GitHub.",
	} {
		if promises := githubSignInPromises("fixture", copy); len(promises) != 0 {
			t.Errorf("flagged unrelated copy: %q", promises)
		}
	}
}

func TestGitHubCopyExceptions(t *testing.T) {
	for path, exceptions := range allowedGitHubCopy {
		content, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		sentences := signInCopySentences(string(content))
		for sentence, reason := range exceptions {
			found := false
			for _, current := range sentences {
				found = found || current == sentence
			}
			if !found || reason == "" || !hasGitHubSignInVocabulary(sentence) {
				t.Errorf("%s: stale or undocumented exact-sentence exception: %q", path, sentence)
			}
			if promises := githubSignInPromises(path, sentence); len(promises) != 0 {
				t.Errorf("%s: exception was not recognized: %q", path, promises)
			}
			if promises := githubSignInPromises(path, sentence+"\n\nSign in via GitHub."); len(promises) != 1 {
				t.Errorf("%s: exception hid an adjacent sign-in promise: %q", path, promises)
			}
			if promises := githubSignInPromises("fixture", sentence); len(promises) != 1 {
				t.Errorf("%s: exception leaked to another file: %q", path, promises)
			}
		}
	}
}

// Email grants and wildcard app handoffs require personal identities, even
// when the relay also offers company login. Scope this check to those flows;
// company/group sharing has separate, valid instructions in README and org-sso.
func TestPersonalAccessCopy(t *testing.T) {
	personalIdentity := regexp.MustCompile(`(?i)\bpersonal(?: tunn)? accounts?\b|\bpersonal sign-in\b`)
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
		{"internal/host/templates/homepage.html", "Alex and Sam sign in", "</p>"},
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
