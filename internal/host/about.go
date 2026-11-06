package host

import (
	_ "embed"
	"html/template"
	"net/http"
	"strings"
)

//go:embed templates/about.html
var aboutHTML string

var aboutTemplate = template.Must(template.New("about").Parse(aboutHTML))

func confirmedFact(value string) string {
	if strings.TrimSpace(value) == "" {
		return "Being confirmed; not currently available."
	}
	return value
}

func (p *ProxyServer) handleAbout(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if r.Method == http.MethodHead {
		return
	}
	var operating, merchant, window string
	if p.config != nil {
		operating, merchant, window = p.config.OperatingName, p.config.MerchantDisplayName, p.config.SupportWindow
	}
	writePageStart(w, "tunn - About and support")
	_ = aboutTemplate.Execute(w, struct {
		OperatingName, MerchantDisplayName, SupportWindow string
		StatusUnpublished                                 bool
	}{confirmedFact(operating), confirmedFact(merchant), confirmedFact(window), p.statusUnconfigured()})
	writePageEnd(w)
}
