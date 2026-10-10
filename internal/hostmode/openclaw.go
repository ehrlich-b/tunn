package hostmode

import (
	"context"
	"fmt"
	"io"
	"net"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

type OpenClawOptions struct {
	Name, Domain, Gateway, ConfigPath, QRFile string
	Probe                                     func(context.Context, string) error
	RenderQR                                  func(context.Context, string, io.Writer, string) error
}

// OpenClaw is a scaffold: the QR contains only the future HTTPS URL, never a
// pairing credential. It neither changes gateway auth nor claims pairing works.
func OpenClaw(ctx context.Context, o OpenClawOptions, out io.Writer) error {
	if !ValidName(o.Name) {
		return fmt.Errorf("provide a valid reserved endpoint --name")
	}
	if o.Domain == "" {
		o.Domain = "tunn.to"
	}
	for _, label := range strings.Split(o.Domain, ".") {
		if !ValidName(label) {
			return fmt.Errorf("invalid endpoint domain")
		}
	}
	if o.Gateway == "" {
		o.Gateway = "http://127.0.0.1:18789"
	}
	u, err := HTTPURL(o.Gateway)
	if err != nil {
		return err
	}
	host := u.Hostname()
	if host == "localhost" {
		host = "127.0.0.1"
	}
	ip := net.ParseIP(host)
	if ip == nil || !ip.IsLoopback() {
		return fmt.Errorf("OpenClaw gateway must be on loopback")
	}
	port := u.Port()
	if port == "" {
		if u.Scheme == "https" {
			port = "443"
		} else {
			port = "80"
		}
	}
	probe := o.Probe
	if probe == nil {
		probe = func(ctx context.Context, addr string) error {
			c, err := (&net.Dialer{Timeout: time.Second}).DialContext(ctx, "tcp", addr)
			if err == nil {
				_ = c.Close()
			}
			return err
		}
	}
	if err := probe(ctx, net.JoinHostPort(host, port)); err != nil {
		fmt.Fprintf(out, "Gateway not detected at %s; start OpenClaw first.\n", u.String())
	} else {
		fmt.Fprintf(out, "Local gateway port reachable at %s (OpenClaw identity unverified).\n", u.String())
	}
	endpointURL := "https://" + o.Name + "." + o.Domain
	fmt.Fprintf(out, "Reserved URL: %s (reservation takes effect after the host service registers).\n", endpointURL)
	fmt.Fprintln(out, "Scaffold: requires the tunn-websocket branch before remote control or phone pairing can work.")
	fmt.Fprintf(out, "1. Run tunn login; add a private http tunnel named %s targeting %s with your email in allow to %s.\n", o.Name, u.String(), strconv.Quote(o.ConfigPath))
	fmt.Fprintf(out, "2. On a relay with TUNN_HOST_MODE=true, run tunn service install --config %s; verify with tunn hosts.\n", strconv.Quote(o.ConfigPath))
	fmt.Fprintln(out, "3. After WebSocket support lands, scan this URL on your phone, authenticate to tunn, and approve the device in OpenClaw. Keep gateway authentication enabled.")
	fmt.Fprintln(out, "Phone setup QR (URL only; does not grant access or enroll a device):")
	render := o.RenderQR
	if render == nil {
		render = RenderQR
	}
	if err := render(ctx, endpointURL, out, o.QRFile); err != nil {
		return err
	}
	return nil
}

// RenderQR uses the local qrencode executable; no URL is fetched.
func RenderQR(ctx context.Context, endpointURL string, out io.Writer, pngPath string) error {
	qrCommand := exec.CommandContext(ctx, "qrencode", "-t", "ANSIUTF8", "--", endpointURL)
	qrCommand.Stdout = out
	if err := qrCommand.Run(); err != nil {
		return fmt.Errorf("render QR: install qrencode and rerun: %w", err)
	}
	if pngPath != "" {
		if err := exec.CommandContext(ctx, "qrencode", "-t", "PNG", "-s", "8", "-m", "4", "-o", pngPath, "--", endpointURL).Run(); err != nil {
			return fmt.Errorf("write QR PNG: %w", err)
		}
		fmt.Fprintf(out, "QR PNG: %s\n", pngPath)
	}
	return nil
}
