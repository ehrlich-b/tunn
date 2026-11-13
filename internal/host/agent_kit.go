package host

import (
	_ "embed"
	"fmt"
	"strings"

	"github.com/ehrlich-b/tunn/skills"
)

//go:embed templates/agents/prompt.md
var agentPromptMarkdown string

type agentKitPage struct {
	path, title, description, body string
}

// Routing and the index share this catalogue; the packaged skill is embedded
// directly rather than copied into the host templates.
var agentKitPages = []agentKitPage{
	{"/agents", "Agent reference", "Install, device login, private HTTP and MCP sharing, and verification.", agentsMarkdown},
	{"/agents/SKILLS.md", "MCP and HTTP procedure", "Commands, connector checks, revocation and trust boundary.", agentsSkillsMarkdown},
	{"/agents/prompt.md", "Install prompt", "A short prompt to paste into any coding agent; replace PORT and EMAILS.", agentPromptMarkdown},
	{"/agents/skill/SKILL.md", "Packaged tunn skill", "Install for Claude Code, Codex or Cursor to share a preview privately.", skills.Tunn},
}

func (p *ProxyServer) agentKitIndex() string {
	var out strings.Builder
	out.WriteString("# tunn\n\n> HTTPS access to a local HTTP app or MCP server, private to its owner by default.\n\n")
	out.WriteString("First login requires human approval of the device code. Never use --public by default.\nUse --allow for named emails; verify an unlisted account receives 403. TLS ends at the relay.\n\n")
	out.WriteString("## Install\n\n```sh\ncurl -fsSL https://tunn.to/install.sh | sh\n```\n\n")
	out.WriteString("## Documentation\n\n- [Quickstart](https://tunn.to/docs): Install, sign in and publish a local port.\n")
	out.WriteString("- [MCP connectors](https://tunn.to/docs/mcp-to-claude): Client setup and connector verification.\n")
	out.WriteString("- [Pricing and limits](https://tunn.to/pricing): Current plans and account allowances.\n")
	out.WriteString("- [Client previews](https://tunn.to/client-previews): Keep a private URL for repeat reviews.\n")
	out.WriteString("- [MCP to Claude](https://tunn.to/mcp-to-claude): Connect a local MCP server to an AI client.\n")
	out.WriteString("- [ngrok alternative](https://tunn.to/ngrok-alternative): Compare tunn with ngrok.\n\n")
	// Share configured amounts and request allowance wording with the pricing page.
	d := p.revenueData()
	out.WriteString("## Plans\n\nUSD before tax. Limits are shared per account; transfer resets monthly.\n\n")
	out.WriteString("| Plan | Price | Concurrent tunnels | Monthly transfer | Requests | Reserved names |\n| --- | --- | --- | --- | --- | --- |\n")
	fmt.Fprintf(&out, "| Free | $0 | %d | %s | %s | %d |\n", d.FreeTunnels, d.FreeBytesShort, d.FreeRequestsShort, d.FreeReservations)
	fmt.Fprintf(&out, "| Pro | $%d/month or $%d/year | %d | %s | %s | %d |\n\n", d.MonthlyUSD, d.YearlyUSD, d.ProTunnels, d.ProBytesShort, d.ProRequestsShort, d.Reservations)
	monthly, yearly := "closed", "closed"
	if d.MonthlyAvailable {
		monthly = "available"
	}
	if d.YearlyAvailable {
		yearly = "available"
	}
	fmt.Fprintf(&out, "Pro checkout: monthly %s; yearly %s.\n\n", monthly, yearly)
	out.WriteString("## For coding agents\n\n")
	for _, page := range agentKitPages {
		fmt.Fprintf(&out, "- [%s](https://tunn.to%s): %s\n", page.title, page.path, page.description)
	}
	return out.String()
}
