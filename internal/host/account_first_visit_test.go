package host

import (
	"bytes"
	"html"
	"html/template"
	"strings"
	"testing"
)

func TestAccountFirstVisitCommands(t *testing.T) {
	f := newWebInspectorFixture(t, 0, 0)
	delete(f.p.tunnelServer.tunnels, f.tunnel.TunnelID)
	for _, route := range []string{"/", "/account"} {
		page := f.call("GET", route, nil, f.cookie, nil)
		if page.Code != 200 {
			t.Fatalf("%s: %d", route, page.Code)
		}
		for _, command := range []string{defaultFirstTunnelCommands.Install, defaultFirstTunnelCommands.Run} {
			if !strings.Contains(page.Body.String(), `data-copy="`+html.EscapeString(command)+`"`) ||
				!strings.Contains(page.Body.String(), `>`+html.EscapeString(command)+`</code>`) {
				t.Errorf("%s: missing displayed/copy command %q", route, command)
			}
		}
	}
	// Different inputs prove both templates bind their code and clipboard values
	// to the shared data, rather than passing through matching hardcoded strings.
	commands := firstTunnelCommands{Install: `install-test --option="a&b"`, Run: "run-test 4567"}
	revenue := f.p.revenueData()
	revenue.FirstTunnelCommands = commands
	account := AccountPageData{revenuePageData: revenue, UsageAvailable: true, LiveTunnelsComplete: true}
	for _, tc := range []struct {
		name, source string
		data         any
	}{
		{"homepage", homepageHTML, revenue},
		{"account", accountHTML, account},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tmpl := template.Must(template.New(tc.name).Funcs(template.FuncMap{"assetURL": webAssetURL}).Parse(tc.source))
			var out bytes.Buffer
			if err := tmpl.Execute(&out, tc.data); err != nil {
				t.Fatal(err)
			}
			for _, command := range []string{commands.Install, commands.Run} {
				value := html.EscapeString(command)
				if !strings.Contains(out.String(), `data-copy="`+value+`"`) || !strings.Contains(out.String(), `>`+value+`</code>`) {
					t.Errorf("shared command %q not used for display and copy", command)
				}
			}
		})
	}
}
