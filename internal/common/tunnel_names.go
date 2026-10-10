package common

import "strings"

// reservedSubdomains are blocked to prevent phishing and squatting
var ReservedTunnelNames = map[string]bool{
	// Infrastructure
	"www": true, "api": true, "app": true, "admin": true, "auth": true,
	"login": true, "static": true, "cdn": true, "assets": true, "images": true,
	"mail": true, "smtp": true, "pop": true, "imap": true, "mx": true,
	"ns": true, "ns1": true, "ns2": true, "dns": true,
	"ftp": true, "sftp": true, "ssh": true, "vpn": true,
	"dev": true, "staging": true, "prod": true, "test": true, "beta": true,
	"status": true, "health": true, "metrics": true, "monitor": true,

	// Common phishing targets
	"google": true, "gmail": true, "youtube": true,
	"facebook": true, "instagram": true, "whatsapp": true, "meta": true,
	"apple": true, "icloud": true, "itunes": true,
	"microsoft": true, "outlook": true, "office": true, "azure": true,
	"amazon": true, "aws": true, "prime": true,
	"paypal": true, "venmo": true, "cashapp": true, "stripe": true,
	"chase": true, "bankofamerica": true, "wellsfargo": true, "citi": true,
	"netflix": true, "spotify": true, "hulu": true, "disney": true,
	"twitter": true, "x": true, "linkedin": true, "tiktok": true,
	"github": true, "gitlab": true, "bitbucket": true,
	"slack": true, "zoom": true, "teams": true, "discord": true,
	"dropbox": true, "box": true, "drive": true,

	// Security-sensitive
	"secure": true, "security": true, "account": true, "accounts": true,
	"billing": true, "payment": true, "pay": true, "checkout": true,
	"verify": true, "verification": true, "confirm": true, "reset": true,
	"password": true, "signin": true, "signup": true, "register": true,
	"support": true, "help": true, "helpdesk": true,
}

// IsReservedTunnelName checks if a tunnel ID is reserved
func IsReservedTunnelName(tunnelID string) bool {
	return ReservedTunnelNames[strings.ToLower(tunnelID)]
}
