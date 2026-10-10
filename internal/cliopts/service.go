package cliopts

import "flag"

type Service struct {
	Config, OS string
	DryRun     bool
}

// ServiceFlags is shared by native installation and caller-side SSH plans.
// The caller supplies defaults because SSH receives a manifest on stdin.
func ServiceFlags(fs *flag.FlagSet, o *Service, config, platform string) {
	fs.StringVar(&o.Config, "config", config, "host manifest path (- for SSH stdin)")
	fs.StringVar(&o.OS, "os", platform, "OS for the native service definition")
	fs.BoolVar(&o.DryRun, "dry-run", false, "print native definitions without installation actions")
}

func ValidServiceAction(action string) bool {
	switch action {
	case "install", "uninstall", "restart", "status", "check", "run":
		return true
	}
	return false
}
