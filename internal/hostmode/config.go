// Package hostmode manages persistent, private endpoints on a user-owned machine.
package hostmode

import (
	"bytes"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

type Config struct {
	Version        int      `yaml:"version"`
	Machine        string   `yaml:"machine"`
	Server         string   `yaml:"server"`
	Domain         string   `yaml:"domain"`
	Insecure       bool     `yaml:"insecure"`
	TokenFile      string   `yaml:"token_file"`
	CredentialsDir string   `yaml:"credentials_dir"`
	Health         string   `yaml:"health"`
	Tunnels        []Tunnel `yaml:"tunnels"`
}

type Tunnel struct {
	NoFavicon bool     `yaml:"no_favicon" json:"-"`
	Name      string   `yaml:"name" json:"name"`
	Kind      string   `yaml:"kind" json:"kind"`
	Target    string   `yaml:"target" json:"-"`
	Allow     []string `yaml:"allow" json:"-"`
	As        string   `yaml:"as" json:"-"`
	Command   []string `yaml:"command" json:"-"`
	Tools     []string `yaml:"tools" json:"-"`
}

func DefaultPath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	root := os.Getenv("XDG_CONFIG_HOME")
	if root == "" {
		root = filepath.Join(home, ".config")
	}
	if !filepath.IsAbs(root) {
		return "", fmt.Errorf("XDG_CONFIG_HOME must be absolute")
	}
	return filepath.Join(root, "tunn", "host.yaml"), nil
}

func Load(path string) (*Config, error) {
	b, err := readPrivateFile(path)
	if err != nil {
		return nil, err
	}
	return Parse(b)
}

func readPrivateFile(path string) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || (runtime.GOOS != "windows" && info.Mode().Perm() != 0600) {
		return nil, fmt.Errorf("%s: require a regular, non-symlink file with mode 0600 (Windows requires a private user ACL)", path)
	}
	return os.ReadFile(path)
}

func Parse(b []byte) (*Config, error) {
	var c Config
	d := yaml.NewDecoder(bytes.NewReader(b))
	d.KnownFields(true)
	if err := d.Decode(&c); err != nil {
		return nil, fmt.Errorf("host config: %w", err)
	}
	var extra any
	if err := d.Decode(&extra); err != io.EOF {
		return nil, fmt.Errorf("host config must contain exactly one YAML document")
	}
	if err := c.Validate(); err != nil {
		return nil, err
	}
	return &c, nil
}

func ValidName(s string) bool {
	if len(s) < 1 || len(s) > 63 || s[0] == '-' || s[len(s)-1] == '-' {
		return false
	}
	for _, r := range s {
		if (r < 'a' || r > 'z') && (r < '0' || r > '9') && r != '-' {
			return false
		}
	}
	return true
}

func (c *Config) Validate() error {
	if c.Version != 1 {
		return fmt.Errorf("host config version must be 1")
	}
	if !ValidName(c.Machine) {
		return fmt.Errorf("machine must be a lowercase DNS label")
	}
	if len(c.Tunnels) == 0 || len(c.Tunnels) > 10 {
		return fmt.Errorf("configure between 1 and 10 tunnels")
	}
	if c.Health == "" {
		c.Health = "127.0.0.1:9087"
	}
	host, port, err := net.SplitHostPort(c.Health)
	if err != nil || net.ParseIP(host) == nil || !net.ParseIP(host).IsLoopback() || !validPort(port, true) {
		return fmt.Errorf("health must be a literal loopback IP and port")
	}
	if c.Server != "" {
		if err := ValidateAddress(c.Server); err != nil {
			return fmt.Errorf("server: %w", err)
		}
	}
	if c.Domain != "" {
		for _, label := range strings.Split(c.Domain, ".") {
			if !ValidName(label) {
				return fmt.Errorf("domain must be a DNS name without a scheme or port")
			}
		}
	}
	if c.TokenFile != "" && !filepath.IsAbs(c.TokenFile) {
		return fmt.Errorf("token_file must be an absolute path")
	}
	if c.CredentialsDir != "" && !filepath.IsAbs(c.CredentialsDir) {
		return fmt.Errorf("credentials_dir must be an absolute path")
	}
	names := map[string]bool{}
	for i := range c.Tunnels {
		t := &c.Tunnels[i]
		if !ValidName(t.Name) || names[t.Name] {
			return fmt.Errorf("invalid or duplicate tunnel name %q", t.Name)
		}
		names[t.Name] = true
		for _, a := range t.Allow {
			if strings.TrimSpace(a) != a || strings.ContainsAny(a, " \r\n\t,") || !strings.Contains(a, "@") || strings.HasSuffix(a, "@") {
				return fmt.Errorf("invalid allow identity on %s", t.Name)
			}
		}
		if t.As != "" && (t.Kind != "unix" || t.As != "http") {
			return fmt.Errorf("as: http applies only to unix tunnels")
		}
		if t.Kind != "mcp" && (len(t.Command) > 0 || len(t.Tools) > 0) {
			return fmt.Errorf("command and tools apply only to mcp tunnels")
		}
		switch t.Kind {
		case "http":
			if len(t.Allow) == 0 {
				return fmt.Errorf("http tunnel %s requires an explicit allow-list", t.Name)
			}
			u, err := HTTPURL(t.Target)
			if err != nil || (u.Path != "" && u.Path != "/") || u.RawQuery != "" {
				return fmt.Errorf("http tunnel %s requires an HTTP origin or port", t.Name)
			}
		case "tcp":
			if err := ValidateAddress(t.Target); err != nil {
				return fmt.Errorf("tcp tunnel %s: %w", t.Name, err)
			}
		case "unix":
			if !filepath.IsAbs(t.Target) {
				return fmt.Errorf("unix tunnel %s requires an absolute socket path", t.Name)
			}
		case "mcp":
			if (len(t.Command) == 0) == (t.Target == "") {
				return fmt.Errorf("mcp tunnel %s requires either target or command", t.Name)
			}
			if len(t.Command) == 0 {
				if _, err := HTTPURL(t.Target); err != nil || len(t.Tools) > 0 {
					return fmt.Errorf("mcp HTTP target is invalid; tools apply only to stdio commands")
				}
			} else if strings.TrimSpace(t.Command[0]) == "" {
				return fmt.Errorf("mcp command must not be empty")
			}
		default:
			return fmt.Errorf("unsupported tunnel kind %q", t.Kind)
		}
	}
	return nil
}

func validPort(s string, zero bool) bool {
	p, err := strconv.Atoi(s)
	return err == nil && p <= 65535 && (p > 0 || zero && p == 0)
}

func ValidateAddress(s string) error {
	h, p, err := net.SplitHostPort(s)
	if err != nil || h == "" || !validPort(p, false) || strings.ContainsAny(h, " /\r\n\t") {
		return fmt.Errorf("expected host:port with port 1–65535")
	}
	return nil
}

func HTTPURL(s string) (*url.URL, error) {
	if validPort(s, false) {
		s = "http://127.0.0.1:" + s
	}
	u, err := url.Parse(s)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Hostname() == "" || u.User != nil || u.Fragment != "" {
		return nil, fmt.Errorf("expected an HTTP(S) URL or port")
	}
	if u.Port() != "" && !validPort(u.Port(), false) {
		return nil, fmt.Errorf("invalid HTTP port")
	}
	return u, nil
}
