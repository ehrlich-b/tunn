package host

// firstTunnelCommands supplies the same quickstart commands to the homepage and
// the account's first-visit state. Keep the displayed value and copy value bound
// to these fields in both templates.
type firstTunnelCommands struct {
	Install string
	Run     string
}

var defaultFirstTunnelCommands = firstTunnelCommands{
	Install: "curl -fsSL https://tunn.to/install.sh | sh",
	Run:     "tunn 3000",
}
