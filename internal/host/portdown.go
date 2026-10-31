package host

import (
	_ "embed"
	"errors"
	"html/template"
	"net/http"
	"strings"
	"time"
)

//go:embed templates/port-down.html
var portDownHTML string

var portDownTemplate = template.Must(template.New("port-down").Parse(portDownHTML))

// localTargetRejectedError reports that the publisher could not open its local target.
type localTargetRejectedError struct{ message string }

func (e *localTargetRejectedError) Error() string {
	return "local target rejected connection: " + e.message
}

// localAppUnreachable is true when the publisher reached tunn but nothing answered locally.
func localAppUnreachable(err error) bool {
	var rejected *localTargetRejectedError
	return errors.As(err, &rejected) && strings.HasPrefix(rejected.message, "failed to reach local")
}

func acceptsHTML(r *http.Request) bool {
	return r.Method == http.MethodGet && strings.Contains(r.Header.Get("Accept"), "text/html")
}

// writeLocalAppDown renders the 502 a browser sees when the local app is not running.
// It is served on the tunnel's own host, so assets are loaded from the platform origin.
func (p *ProxyServer) writeLocalAppDown(w http.ResponseWriter, r *http.Request) {
	var body strings.Builder
	_ = portDownTemplate.Execute(&body, struct {
		Host, Path, Time string
	}{requestHostname(r.Host), r.URL.Path, time.Now().UTC().Format("15:04:05")})
	writeBrowserError(w, http.StatusBadGateway, browserErrorPage{
		Label: "App unavailable", Title: "Local app not answering",
		Detail: "The tunnel is reachable, but its local app is not responding.",
		Body:   template.HTML(body.String()), Action: "Reload", Href: "",
	}, p.Domain, p.statusUnconfigured())
}
