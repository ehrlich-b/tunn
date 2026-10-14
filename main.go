package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/ehrlich-b/tunn/internal/client"
	"github.com/ehrlich-b/tunn/internal/cliopts"
	"github.com/ehrlich-b/tunn/internal/common"
	"github.com/ehrlich-b/tunn/internal/config"
	"github.com/ehrlich-b/tunn/internal/domains"
	"github.com/ehrlich-b/tunn/internal/host"
	"github.com/ehrlich-b/tunn/internal/hostmode"
	"github.com/ehrlich-b/tunn/internal/mcpbridge"
	"github.com/ehrlich-b/tunn/internal/relaytransport"
	pb "github.com/ehrlich-b/tunn/pkg/proto/tunnelv1"
	"github.com/golang-jwt/jwt/v4"
	"github.com/joho/godotenv"
)

// Global flags (parsed before subcommand)
var (
	verbosity = flag.String("verbosity", "request", "log level: none, error, request, trace")
	insecure  = flag.Bool("insecure", false, "skip TLS verification for proxy gRPC connection (insecure)")
	dev       = flag.Bool("dev", false, "use development configuration (or set TUNN_ENV=dev)")

	// Hidden flag for server operators
	mode = flag.String("mode", "", "internal: host mode for server operators")

	// Host mode flags
	domain   = flag.String("domain", "tunn.to", "public apex domain")
	certFile = flag.String("cert", "/app/certs/fullchain.pem", "TLS certificate file (host mode)")
	keyFile  = flag.String("key", "/app/certs/privkey.pem", "TLS private key file (host mode)")
)

func main() {
	// Load .env file if present (silently ignored if not found)
	_ = godotenv.Load()

	// Custom usage message
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, `tunn - expose localhost to the internet

Usage:
  tunn <port>                    Tunnel localhost:<port> to a public URL
  tunn <host:port>               Tunnel host:port to a public URL
  tunn <url>                     Tunnel any URL to a public URL
  tunn service install|uninstall|restart|status|check  Manage persistent machine endpoints
  tunn hosts [--json]             List your machines and their tunnels
  tunn openclaw [options]         Preview OpenClaw phone setup (needs WebSockets)
  tunn keys add|list|remove       Manage account SSH public keys
  tunn login                     Authenticate with GitHub
  tunn serve [options] <target>  Explicit serve mode (same as default)
  tunn http [options] <target>   Shortcut for ngrok-style HTTP usage
  tunn mcp [options] <command…>   Connect a local MCP server to an AI agent
  tunn connector-check [options] <url>  Diagnose a private MCP connector
  tunn tcp [options] <host:port>  Publish a private raw TCP endpoint
  tunn unix [options] <path>      Publish a private Unix socket
  tunn connect [options] <name>   Open a remote TCP endpoint locally
  tunn token [--rotate] <name>   Print or rotate an endpoint access token
  tunn ip-policy <action>        Manage endpoint or account IP restrictions
  tunn usage <name>              Export caller usage and audit decisions
  tunn share <name> <recipient>  Share web access: email or group:ORG:GROUP
  tunn unshare <name> <recipient> Revoke web access and active streams
  tunn access <name>             Show who has access
  tunn grant create <name>       Issue a metered, expiring consumer token
  tunn grant revoke <name> <id>  Revoke one consumer grant
  tunn policy login|get|set|clear Configure request headers and rate limits
  tunn domain add|verify|list|delete  Manage Pro custom domains
  tunn status serve|incident|resolve  Relay probe history and local incident notes
  tunn admin --help             Local authenticated account and billing controls

Examples:
  tunn 8080                              # https://abc123.tunn.to -> localhost:8080
  tunn 8080 --allow=alice@gmail.com      # Share with specific people
  tunn localhost:3000                    # Tunnel localhost:3000
  tunn http://api.local:9000             # Tunnel any URL
  tunn mcp -- npx -y @modelcontextprotocol/server-filesystem .
  tunn tcp --name database localhost:5432
  tunn unix --name docker /var/run/docker.sock
  tunn connect --listen 127.0.0.1:15432 database

Options:
`)
		flag.PrintDefaults()
	}

	// Parse global flags first, but stop at first non-flag
	flag.Parse()
	args := flag.Args()
	if *dev {
		_ = os.Setenv("TUNN_ENV", "dev")
	}

	// Setup logging
	logLevel := common.ParseLogLevel(*verbosity)
	common.SetLogLevel(logLevel)

	// Handle hidden -mode=host for server operators
	if *mode == "host" {
		runHost()
		return
	}

	// No args? Show help
	if len(args) == 0 {
		flag.Usage()
		os.Exit(0)
	}

	// Route to subcommand or default serve behavior
	switch args[0] {
	case "status":
		runStatus(args[1:])
	case "admin":
		runOperations(args[1:])
	case "service", "hosts", "openclaw":
		runHostCommand(args[0], args[1:])
	case "keys":
		runKeys(args[1:])
	case "login":
		runLogin()
	case "serve", "http":
		runServe(args[1:])
	case "mcp":
		runMCP(args[1:])
	case "connector-check":
		runConnectorCheck(args[1:])
	case "tcp":
		runTCP(args[1:])
	case "unix":
		runUnix(args[1:])
	case "connect":
		runConnect(args[1:])
	case "token":
		runEndpointToken(args[1:])
	case "policy":
		runPolicy(args[1:])
	case "domain":
		runDomains(args[1:])
	case "share", "unshare", "access":
		runSharing(args[0], args[1:])
	case "ip-policy":
		runIPPolicy(args[1:])
	case "usage", "grant":
		runMetering(args[0], args[1:])
	case "magic-link":
		runMagicLink(args[1:])
	case "help", "-h", "--help":
		flag.Usage()
		os.Exit(0)
	default:
		// Default: treat first arg as target, rest as flags
		runServe(args)
	}
}

type mcpCommandOptions struct {
	tunnelID      string
	allowedEmails []string
	tunnelKey     string
	clientSecret  string
	public        bool
	command       []string
	targetURL     string
	allowedTools  []string
}

func parseMCPFlags(args []string) (*mcpCommandOptions, error) {
	separator := -1
	for index, arg := range args {
		if arg == "--" {
			separator = index
			break
		}
	}
	if separator != -1 && separator == len(args)-1 {
		return nil, fmt.Errorf("MCP command is required after --")
	}

	fs := flag.NewFlagSet("mcp", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	shared := new(cliopts.Serve)
	cliopts.PublicationFlags(fs, shared)
	var allowedTools []string
	cliopts.MCPToolFlag(fs, &allowedTools)

	flagArgs := args
	if separator != -1 {
		flagArgs = args[:separator]
	}
	if err := fs.Parse(flagArgs); err != nil {
		return nil, err
	}
	if separator != -1 && fs.NArg() != 0 {
		return nil, fmt.Errorf("unexpected argument before --: %s", fs.Arg(0))
	}
	if separator == -1 && fs.NArg() != 1 {
		return nil, fmt.Errorf("provide one MCP HTTP URL, or use -- before a stdio command")
	}

	tunnelID, allowedEmails := shared.Name, shared.AllowedEmails
	if shared.Public && len(allowedEmails) > 0 {
		return nil, fmt.Errorf("--public and --allow cannot be used together")
	}

	clientSecret := shared.Secret
	if clientSecret == "" {
		clientSecret = os.Getenv("TUNN_SECRET")
	}

	opts := &mcpCommandOptions{
		tunnelID:      tunnelID,
		allowedEmails: allowedEmails,
		tunnelKey:     shared.TunnelKey,
		clientSecret:  clientSecret,
		public:        shared.Public,
		allowedTools:  allowedTools,
	}
	if separator == -1 {
		if len(allowedTools) > 0 {
			return nil, fmt.Errorf("--tools currently applies only to stdio MCP commands")
		}
		if _, _, _, err := splitMCPUpstreamURL(fs.Arg(0)); err != nil {
			return nil, fmt.Errorf("invalid MCP HTTP URL: %w", err)
		}
		opts.targetURL = fs.Arg(0)
	} else {
		opts.command = append([]string(nil), args[separator+1:]...)
	}
	return opts, nil
}

func printMCPUsage() {
	fmt.Fprintln(os.Stderr, `tunn mcp - expose a local stdio MCP server

Usage:
  tunn mcp [options] <command> [args...]
  tunn mcp [options] -- <command> [args...]
  tunn mcp [options] <http-url>

Examples:
  tunn mcp --tools echo -- python3 examples/mcp/echo.py
  tunn mcp --name work -- docker mcp gateway run --profile work
  tunn mcp --name local http://127.0.0.1:3000/mcp
  tunn mcp --public -- ./my-mcp-server

Options:
  --name, --id <name>       Endpoint name (blank generates one)
  --allow <emails>          Share with additional tunn account emails
  --public                  Explicitly allow unauthenticated access
  --tools <names>           Exact comma-separated tool allow-list (stdio only)
  --tunnel-key <key>        Tunnel creation authorization key
  --secret <secret>         Self-hosted client authentication secret

After publishing, run tunn connector-check --oauth --expect-tools echo <Connector-URL>.
Guide: https://tunn.to/mcp-to-claude`)
}

func runMCP(args []string) {
	opts, err := parseMCPFlags(normalizeMCPArgs(args))
	if errors.Is(err, flag.ErrHelp) {
		printMCPUsage()
		return
	}
	if err != nil {
		common.LogError("invalid MCP command", "error", err)
		printMCPUsage()
		os.Exit(1)
	}

	cfg, err := config.LoadConfig()
	if err != nil {
		common.LogError("failed to load config", "error", err)
		os.Exit(1)
	}

	var credentials *client.CredentialManager
	var token string
	if opts.clientSecret != "" {
		token = opts.clientSecret
	} else if !cfg.PublicMode {
		token, credentials, err = loadPublisherToken(context.Background(), cfg.ServerAddr, cfg.Insecure || *insecure)
		if err != nil {
			exitIfLoginRequired(err)
			common.LogError("not logged in - run 'tunn login' first", "error", err)
			os.Exit(1)
		}
	}

	tunnelKey := opts.tunnelKey
	if tunnelKey == "" {
		tunnelKey = cfg.WellKnownKey
		if tunnelKey == "" {
			common.LogError("tunnel key not provided - use --tunnel-key or set WELL_KNOWN_KEY")
			os.Exit(1)
		}
	}

	tunnelID := opts.tunnelID
	if tunnelID == "" {
		tunnelID = common.RandID(7)
	}

	allowedEmails := append([]string(nil), opts.allowedEmails...)
	creatorEmail := ""
	var accessTokenSHA256 []byte
	endpointTokenPath := ""
	if !opts.public {
		creatorEmail, err = common.ExtractEmailFromJWT(token)
		if err != nil && len(allowedEmails) == 0 {
			common.LogError("private MCP endpoints require a tunn login token or an explicit --allow", "error", err)
			os.Exit(1)
		}
		if creatorEmail != "" {
			allowedEmails = appendUniqueEmail(allowedEmails, creatorEmail)
		}

		endpointToken, digest, err := client.GenerateEndpointToken()
		if err != nil {
			common.LogError("failed to generate endpoint token", "error", err)
			os.Exit(1)
		}
		endpointTokenPath, err = client.SaveEndpointToken(tunnelID, endpointToken)
		if err != nil {
			common.LogError("failed to store endpoint token", "error", err)
			os.Exit(1)
		}
		accessTokenSHA256 = digest
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sigChan
		common.LogInfo("received shutdown signal")
		cancel()
	}()

	targetURL := ""
	displayTarget := ""
	upstreamPath := ""
	upstreamRawQuery := ""
	var bridge *mcpbridge.Bridge
	var childDone <-chan struct{}
	cleanupBridge := func() {}
	if len(opts.command) > 0 {
		bridge, err = mcpbridge.StartWithOptions(ctx, opts.command, os.Stderr, mcpbridge.Options{AllowedTools: opts.allowedTools})
		if err != nil {
			common.LogError("failed to start local MCP server", "error", err)
			os.Exit(1)
		}
		targetURL = bridge.URL()
		displayTarget = "stdio:" + opts.command[0]
		childDone = bridge.Done()
		cleanupBridge = func() {
			shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer shutdownCancel()
			_ = bridge.Close(shutdownCtx)
		}
	} else {
		if len(opts.allowedTools) > 0 {
			common.LogError("--tools currently applies only to stdio MCP commands")
			os.Exit(1)
		}
		targetURL, upstreamPath, upstreamRawQuery, err = splitMCPUpstreamURL(opts.targetURL)
		if err != nil {
			common.LogError("invalid MCP HTTP URL", "error", err)
			os.Exit(1)
		}
		displayTarget = opts.targetURL
	}
	defer cleanupBridge()

	serveClient := &client.ServeClient{
		TunnelID:          tunnelID,
		TargetURL:         targetURL,
		DisplayTarget:     displayTarget,
		PublicPath:        "/mcp",
		UpstreamPath:      upstreamPath,
		UpstreamRawQuery:  upstreamRawQuery,
		ServerAddr:        cfg.ServerAddr,
		AuthToken:         token,
		Credentials:       credentials,
		CreatorEmail:      creatorEmail,
		AccessTokenSHA256: accessTokenSHA256,
		EndpointTokenPath: endpointTokenPath,
		TunnelKey:         tunnelKey,
		AllowedEmails:     allowedEmails,
		Insecure:          cfg.Insecure || *insecure,
		HTTPTimeout:       27 * time.Second,
	}

	tunnelResult := make(chan error, 1)
	go func() {
		tunnelResult <- serveClient.Run(ctx)
	}()

	var runErr error
	select {
	case err := <-tunnelResult:
		if err == nil && ctx.Err() == nil {
			runErr = fmt.Errorf("tunnel stopped unexpectedly")
		} else {
			runErr = err
		}
	case <-childDone:
		childErr := bridge.Wait()
		if ctx.Err() == nil {
			if childErr == nil {
				runErr = fmt.Errorf("local MCP process exited")
			} else {
				runErr = fmt.Errorf("local MCP process exited: %w", childErr)
			}
		}
		cancel()
	case <-ctx.Done():
		runErr = ctx.Err()
	}

	if runErr != nil && !errors.Is(runErr, context.Canceled) {
		cancel()
		cleanupBridge()
		exitIfLoginRequired(runErr)
		common.LogError("MCP tunnel stopped", "error", runErr)
		os.Exit(1)
	}
}

func splitMCPUpstreamURL(raw string) (baseURL, path, rawQuery string, err error) {
	parsed, err := url.Parse(raw)
	if err != nil {
		return "", "", "", err
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return "", "", "", fmt.Errorf("URL scheme must be http or https")
	}
	if parsed.Host == "" {
		return "", "", "", fmt.Errorf("URL must include a host")
	}
	if parsed.User != nil {
		return "", "", "", fmt.Errorf("credentials in the URL are not supported; use an Authorization header")
	}
	if parsed.Fragment != "" {
		return "", "", "", fmt.Errorf("URL fragments are not sent to MCP servers")
	}
	path = parsed.EscapedPath()
	if path == "" {
		path = "/mcp"
	}
	return parsed.Scheme + "://" + parsed.Host, path, parsed.RawQuery, nil
}

func runEndpointToken(args []string) {
	fs := flag.NewFlagSet("token", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	rotate := fs.Bool("rotate", false, "atomically replace the endpoint token")
	if err := fs.Parse(args); err != nil || fs.NArg() != 1 {
		common.LogError("endpoint name required: tunn token [--rotate] <endpoint>")
		os.Exit(1)
	}
	endpointName := fs.Arg(0)
	if *rotate {
		token, path, err := client.RotateEndpointToken(endpointName)
		if err != nil {
			common.LogError("failed to rotate endpoint token", "error", err)
			os.Exit(1)
		}
		fmt.Println(token)
		fmt.Fprintf(os.Stderr, "Rotated %s; a running endpoint will update within one second.\n", path)
		return
	}
	token, err := client.LoadEndpointToken(endpointName)
	if err != nil {
		common.LogError("failed to load endpoint token", "error", err)
		os.Exit(1)
	}
	fmt.Println(token)
}

type tcpCommandOptions struct {
	tunnelID      string
	allowedEmails []string
	tunnelKey     string
	clientSecret  string
	public        bool
	target        string
	adapter       string
	accountOnly   bool
}

func parseTCPFlags(args []string) (*tcpCommandOptions, error) {
	opts, err := parseRawPublisherFlags("tcp", args, normalizeTCPTarget)
	if err == nil && opts.adapter != "raw" {
		return nil, fmt.Errorf("tunn tcp supports only --as raw")
	}
	return opts, err
}

func parseUnixFlags(args []string) (*tcpCommandOptions, error) {
	opts, err := parseRawPublisherFlags("unix", args, normalizeUnixTarget)
	if err != nil {
		return nil, err
	}
	if opts.adapter != "raw" && opts.adapter != "http" {
		return nil, fmt.Errorf("--as must be raw or http")
	}
	if opts.adapter == "http" && opts.public {
		return nil, fmt.Errorf("HTTP-over-Unix endpoints cannot be public")
	}
	return opts, nil
}

func parseRawPublisherFlags(command string, args []string, normalize func(string) (string, error)) (*tcpCommandOptions, error) {
	fs := flag.NewFlagSet(command, flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	shared := new(cliopts.Serve)
	cliopts.PublicationFlags(fs, shared)
	asFlag := fs.String("as", "raw", "adapter: raw or http (Unix sockets)")
	accountOnly := fs.Bool("account-only", false, "require account login; do not create an endpoint bearer token")
	if err := fs.Parse(args); err != nil {
		return nil, err
	}
	if fs.NArg() != 1 {
		return nil, fmt.Errorf("provide one %s target", command)
	}
	target, err := normalize(fs.Arg(0))
	if err != nil {
		return nil, err
	}

	allowedEmails, tunnelID := shared.AllowedEmails, shared.Name
	if shared.Public && (len(allowedEmails) > 0 || *accountOnly) {
		return nil, fmt.Errorf("--public cannot be combined with --allow or --account-only")
	}

	clientSecret := shared.Secret
	if clientSecret == "" {
		clientSecret = os.Getenv("TUNN_SECRET")
	}
	return &tcpCommandOptions{
		tunnelID:      tunnelID,
		allowedEmails: allowedEmails,
		tunnelKey:     shared.TunnelKey,
		clientSecret:  clientSecret,
		public:        shared.Public,
		target:        target,
		adapter:       strings.ToLower(strings.TrimSpace(*asFlag)),
		accountOnly:   *accountOnly,
	}, nil
}

func normalizeTCPTarget(target string) (string, error) {
	if target == "" {
		return "", fmt.Errorf("TCP target is empty")
	}
	if port, err := strconv.Atoi(target); err == nil {
		target = net.JoinHostPort("127.0.0.1", strconv.Itoa(port))
	}
	host, portText, err := net.SplitHostPort(target)
	if err != nil || host == "" {
		return "", fmt.Errorf("invalid TCP target %q; expected host:port", target)
	}
	port, err := strconv.Atoi(portText)
	if err != nil || port < 1 || port > 65535 {
		return "", fmt.Errorf("invalid TCP port %q", portText)
	}
	return net.JoinHostPort(host, strconv.Itoa(port)), nil
}

func normalizeUnixTarget(target string) (string, error) {
	if !filepath.IsAbs(target) || strings.ContainsRune(target, '\x00') {
		return "", fmt.Errorf("unix socket path must be absolute")
	}
	return filepath.Clean(target), nil
}

func runTCP(args []string) {
	opts, err := parseTCPFlags(args)
	if err != nil {
		common.LogError("invalid TCP endpoint", "error", err)
		fmt.Fprintln(os.Stderr, "Usage: tunn tcp [--name NAME] [--allow EMAILS|--public] <host:port>")
		os.Exit(1)
	}
	runRawPublisher(opts, "tcp", "tcp")
}

func runUnix(args []string) {
	opts, err := parseUnixFlags(args)
	if err != nil {
		common.LogError("invalid Unix endpoint", "error", err)
		fmt.Fprintln(os.Stderr, "Usage: tunn unix [--name NAME] [--allow EMAILS|--public] </absolute/socket/path>")
		os.Exit(1)
	}
	endpointProtocol := "tcp"
	if opts.adapter == "http" {
		endpointProtocol = "http"
	}
	runRawPublisher(opts, "unix", endpointProtocol)
}

func runRawPublisher(opts *tcpCommandOptions, targetNetwork, endpointProtocol string) {
	cfg, err := config.LoadConfig()
	if err != nil {
		common.LogError("failed to load config", "error", err)
		os.Exit(1)
	}

	var credentials *client.CredentialManager
	token := opts.clientSecret
	if token == "" && !cfg.PublicMode {
		token, credentials, err = loadPublisherToken(context.Background(), cfg.ServerAddr, cfg.Insecure || *insecure)
		if err != nil {
			exitIfLoginRequired(err)
			common.LogError("not logged in - run 'tunn login' first", "error", err)
			os.Exit(1)
		}
	}
	tunnelKey := opts.tunnelKey
	if tunnelKey == "" {
		tunnelKey = cfg.WellKnownKey
	}
	if tunnelKey == "" {
		common.LogError("tunnel key not provided - use --tunnel-key or set WELL_KNOWN_KEY")
		os.Exit(1)
	}
	tunnelID := opts.tunnelID
	if tunnelID == "" {
		tunnelID = common.RandID(7)
	}

	allowedEmails := append([]string(nil), opts.allowedEmails...)
	creatorEmail := ""
	var accessTokenSHA256 []byte
	endpointTokenPath := ""
	if !opts.public {
		creatorEmail, err = common.ExtractEmailFromJWT(token)
		if err != nil && len(allowedEmails) == 0 {
			common.LogError("private raw endpoints require a tunn login token or an explicit --allow", "error", err)
			os.Exit(1)
		}
		if creatorEmail != "" {
			allowedEmails = appendUniqueEmail(allowedEmails, creatorEmail)
		}
		if !opts.accountOnly {
			endpointToken, digest, err := client.GenerateEndpointToken()
			if err != nil {
				common.LogError("failed to generate endpoint token", "error", err)
				os.Exit(1)
			}
			endpointTokenPath, err = client.SaveEndpointToken(tunnelID, endpointToken)
			if err != nil {
				common.LogError("failed to store endpoint token", "error", err)
				os.Exit(1)
			}
			accessTokenSHA256 = digest
		}
	}

	ctx, cancel := signalContext()
	defer cancel()
	targetURL := opts.target
	dialAddress := ""
	publicPath := common.TCPConnectPath
	if endpointProtocol == "http" {
		targetURL = "http://unix"
		dialAddress = opts.target
		publicPath = ""
	}
	serveClient := &client.ServeClient{
		TunnelID:          tunnelID,
		TargetURL:         targetURL,
		DisplayTarget:     targetNetwork + "://" + opts.target,
		PublicPath:        publicPath,
		ServerAddr:        cfg.ServerAddr,
		AuthToken:         token,
		Credentials:       credentials,
		CreatorEmail:      creatorEmail,
		AccessTokenSHA256: accessTokenSHA256,
		EndpointTokenPath: endpointTokenPath,
		EndpointProtocol:  endpointProtocol,
		TargetNetwork:     targetNetwork,
		DialAddress:       dialAddress,
		TunnelKey:         tunnelKey,
		AllowedEmails:     allowedEmails,
		Insecure:          cfg.Insecure || *insecure,
	}
	if err := serveClient.Run(ctx); err != nil && !errors.Is(err, context.Canceled) {
		exitIfLoginRequired(err)
		common.LogError("raw endpoint failed", "error", err)
		os.Exit(1)
	}
}

type connectCommandOptions struct {
	endpoint  string
	listen    string
	token     string
	tokenFile string
	public    bool
	account   bool
	stdio     bool
}

func parseConnectFlags(args []string) (*connectCommandOptions, error) {
	fs := flag.NewFlagSet("connect", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	listenFlag := fs.String("listen", "127.0.0.1:0", "local listen address")
	tokenFlag := fs.String("token", "", "endpoint token (prefer --token-file or TUNN_ENDPOINT_TOKEN)")
	tokenFileFlag := fs.String("token-file", "", "file containing the endpoint token")
	publicFlag := fs.Bool("public", false, "connect without an endpoint token")
	accountFlag := fs.Bool("account", false, "use renewable account login")
	stdioFlag := fs.Bool("stdio", false, "bridge stdin/stdout for an SSH ProxyCommand")
	if err := fs.Parse(args); err != nil {
		return nil, err
	}
	if fs.NArg() != 1 {
		return nil, fmt.Errorf("provide one endpoint name or URL")
	}
	listenSet := false
	fs.Visit(func(f *flag.Flag) {
		if f.Name == "listen" {
			listenSet = true
		}
	})
	if *stdioFlag && listenSet {
		return nil, fmt.Errorf("--stdio and --listen cannot be combined")
	}
	if *accountFlag && (*publicFlag || *tokenFlag != "" || *tokenFileFlag != "") {
		return nil, fmt.Errorf("--account cannot be combined with --public or endpoint credentials")
	}
	if *tokenFlag != "" && *tokenFileFlag != "" {
		return nil, fmt.Errorf("--token and --token-file cannot be used together")
	}
	if _, err := net.ResolveTCPAddr("tcp", *listenFlag); err != nil {
		return nil, fmt.Errorf("invalid listen address: %w", err)
	}
	return &connectCommandOptions{endpoint: fs.Arg(0), listen: *listenFlag, token: *tokenFlag, tokenFile: *tokenFileFlag, public: *publicFlag, account: *accountFlag, stdio: *stdioFlag}, nil
}

func runConnect(args []string) {
	opts, err := parseConnectFlags(args)
	if err != nil {
		common.LogError("invalid connect command", "error", err)
		fmt.Fprintln(os.Stderr, "Usage: tunn connect [--listen 127.0.0.1:PORT] [--token-file FILE] <endpoint>")
		os.Exit(1)
	}
	cfg, err := config.LoadConfig()
	if err != nil {
		common.LogError("failed to load config", "error", err)
		os.Exit(1)
	}
	endpointURL, endpointName, err := resolveConnectEndpoint(opts.endpoint, cfg.Domain, cfg.ServerAddr)
	if err != nil {
		common.LogError("invalid endpoint", "error", err)
		os.Exit(1)
	}
	var credentials *client.CredentialManager
	token := opts.token
	if opts.account {
		if endpointName == "" {
			common.LogError("--account requires an endpoint name on the configured relay")
			os.Exit(1)
		}
		token, credentials, err = client.LoadTunnelToken(context.Background(), cfg.ServerAddr, cfg.Insecure || *insecure)
		if err != nil {
			common.LogError("account login unavailable", "error", err)
			os.Exit(1)
		}
	}
	if token == "" && opts.tokenFile != "" {
		data, readErr := os.ReadFile(opts.tokenFile)
		if readErr != nil {
			common.LogError("failed to read endpoint token", "error", readErr)
			os.Exit(1)
		}
		token = strings.TrimSpace(string(data))
	}
	if token == "" {
		token = os.Getenv("TUNN_ENDPOINT_TOKEN")
	}
	if token == "" && endpointName != "" {
		token, _ = client.LoadEndpointToken(endpointName)
	}
	if token == "" && !opts.public {
		common.LogError("endpoint token required; use --token-file or TUNN_ENDPOINT_TOKEN")
		os.Exit(1)
	}

	ctx, cancel := signalContext()
	defer cancel()
	connector := &client.ConnectClient{
		EndpointURL: endpointURL,
		Token:       token,
		Credentials: credentials,
		ListenAddr:  opts.listen,
		Insecure:    cfg.Insecure || *insecure,
	}
	if opts.stdio {
		err = connector.RunStdio(ctx, os.Stdin, os.Stdout)
	} else {
		err = connector.Run(ctx)
	}
	if err != nil && !errors.Is(err, context.Canceled) {
		common.LogError("TCP connector failed", "error", err)
		os.Exit(1)
	}
}

func resolveConnectEndpoint(value, configuredDomain, serverAddr string) (endpointURL, endpointName string, err error) {
	if strings.Contains(value, "://") {
		parsed, err := url.Parse(value)
		if err != nil || parsed.Host == "" || parsed.Scheme != "https" {
			return "", "", fmt.Errorf("remote endpoint URL must use https")
		}
		if parsed.User != nil || parsed.Fragment != "" {
			return "", "", fmt.Errorf("endpoint URL cannot contain credentials or a fragment")
		}
		parsed.Path = common.TCPConnectPath
		parsed.RawPath = ""
		parsed.RawQuery = ""
		// Explicit URLs never trigger automatic local-token lookup. Otherwise a
		// same-named host on an unrelated domain could steal a saved token.
		return parsed.String(), "", nil
	}
	if !isValidEndpointName(value) {
		return "", "", fmt.Errorf("invalid endpoint name %q", value)
	}

	domain := configuredDomain
	serverHost := serverAddr
	if host, _, splitErr := net.SplitHostPort(serverAddr); splitErr == nil {
		serverHost = host
	}
	if serverHost == "tunn.to" || domain == "" {
		domain = serverHost
	}
	return "https://" + strings.ToLower(value) + "." + domain + common.TCPConnectPath, strings.ToLower(value), nil
}

func isValidEndpointName(value string) bool {
	value = strings.ToLower(strings.TrimSpace(value))
	if len(value) == 0 || len(value) > 63 || value[0] == '-' || value[len(value)-1] == '-' {
		return false
	}
	for _, character := range value {
		if (character < 'a' || character > 'z') && (character < '0' || character > '9') && character != '-' {
			return false
		}
	}
	return true
}

func signalContext() (context.Context, context.CancelFunc) {
	ctx, cancel := context.WithCancel(context.Background())
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	go func() {
		select {
		case <-sigChan:
			common.LogInfo("received shutdown signal")
			cancel()
		case <-ctx.Done():
		}
	}()
	return ctx, cancel
}

func appendUniqueEmail(emails []string, email string) []string {
	normalized := common.NormalizeEmail(email)
	for _, existing := range emails {
		if common.NormalizeEmail(existing) == normalized {
			return emails
		}
	}
	return append(emails, normalized)
}

type serveCommandOptions struct {
	webhookProvider, webhookSecretFile string
	webhookTolerance                   time.Duration
	expire                             time.Duration
	qr, public                         bool
	target                             string
	tunnelID                           string
	namespace                          string
	allowedEmails                      []string
	tunnelKey                          string
	clientSecret                       string
	skipLocalTLSVerify                 bool
	inspect                            bool
	inspectBody                        bool
	bearer                             bool
	requireUpstreamAuth                bool
	webSocket                          common.WebSocketOptions
}

func parseServeFlags(args []string) (*serveCommandOptions, error) {
	o, err := cliopts.ParseServe(args, true)
	if err != nil {
		return nil, err
	}
	if o.Namespace != "" {
		if !isValidEndpointName(o.Name) || common.IsReservedTunnelName(o.Name) {
			return nil, fmt.Errorf("--namespace requires a valid --name app label")
		}
		if _, err := domains.NormalizeName("*."+strings.TrimPrefix(o.Namespace, "*."), ""); err != nil {
			return nil, fmt.Errorf("invalid --namespace: %w", err)
		}
	}
	if o.Secret == "" {
		o.Secret = os.Getenv("TUNN_SECRET")
	}
	return &serveCommandOptions{webhookProvider: o.WebhookProvider, webhookSecretFile: o.WebhookSecretFile, webhookTolerance: o.WebhookTolerance, target: o.Target, tunnelID: o.Name, namespace: o.Namespace, allowedEmails: o.AllowedEmails, tunnelKey: o.TunnelKey, clientSecret: o.Secret, skipLocalTLSVerify: o.SkipLocalTLSVerify, inspect: o.Inspect, inspectBody: o.InspectBody, bearer: o.Bearer, requireUpstreamAuth: o.RequireUpstreamAuth, webSocket: o.WebSocket, expire: o.Expire, qr: o.QR, public: o.Public}, nil
}

func runLogin() {
	cfg, err := config.LoadConfig()
	if err != nil {
		common.LogError("failed to load config", "error", err)
		os.Exit(1)
	}

	loginClient := &client.LoginClient{
		ServerAddr: cfg.ServerAddr,
		Insecure:   cfg.Insecure || *insecure,
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sigChan
		common.LogInfo("received shutdown signal")
		cancel()
	}()

	if err := loginClient.Run(ctx); err != nil && err != context.Canceled {
		common.LogError("login failed", "error", err)
		os.Exit(1)
	}
}

func runHost() {
	cfg, err := config.LoadConfig()
	if err != nil {
		common.LogError("failed to load config", "error", err)
		os.Exit(1)
	}

	// Override config with flags if provided
	if *domain != "tunn.to" {
		cfg.Domain = *domain
	}
	if *certFile != "/app/certs/fullchain.pem" {
		cfg.CertFile = *certFile
	}
	if *keyFile != "/app/certs/privkey.pem" {
		cfg.KeyFile = *keyFile
	}
	if err := cfg.ValidateHost(); err != nil {
		common.LogError("invalid host configuration", "error", err)
		os.Exit(1)
	}

	proxy, err := host.NewProxyServer(cfg)
	if err != nil {
		common.LogError("failed to create proxy server", "error", err)
		os.Exit(1)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sigChan
		common.LogInfo("received shutdown signal")
		cancel()
	}()

	if err := proxy.Run(ctx); err != nil && err != context.Canceled {
		common.LogError("proxy server error", "error", err)
		os.Exit(1)
	}
}

func runServe(args []string) {
	opts, err := parseServeFlags(args)
	if err != nil {
		if errors.Is(err, flag.ErrHelp) {
			printServeUsage()
			return
		}
		common.LogError("invalid serve command", "error", err)
		printServeUsage()
		os.Exit(1)
	}
	var webhookSecret []byte
	if opts.webhookProvider != "" {
		webhookSecret, err = client.LoadWebhookSecret(opts.webhookSecretFile)
		if err != nil {
			common.LogError("invalid webhook secret file", "error", err)
			os.Exit(1)
		}
	}
	target, tunnelID, allowedEmails, tunnelKey, clientSecret := opts.target, opts.tunnelID, opts.allowedEmails, opts.tunnelKey, opts.clientSecret

	cfg, err := config.LoadConfig()
	if err != nil {
		common.LogError("failed to load config", "error", err)
		os.Exit(1)
	}

	// Determine auth token: client secret OR JWT from login
	var credentials *client.CredentialManager
	var token string
	if clientSecret != "" {
		// Use client secret as auth token (self-hosters)
		token = clientSecret
	} else if !cfg.PublicMode {
		login := &client.LoginClient{ServerAddr: cfg.ServerAddr, Insecure: cfg.Insecure || *insecure}
		token, credentials, err = loadOrEnrollWebPublisher(context.Background(), cfg.ServerAddr, cfg.Insecure || *insecure, stdinIsTerminal(), loadPublisherToken, login.Run)
		if err != nil {
			exitIfLoginRequired(err)
			common.LogError("publisher enrollment failed", "error", err)
			os.Exit(1)
		}

	}

	if opts.namespace != "" {
		transport := relaytransport.Transport(cfg.Insecure || *insecure)
		management := &client.ManagementClient{ServerURL: cfg.ServerAddr, OwnerToken: token, HTTPClient: &http.Client{Transport: transport, Timeout: 30 * time.Second}}
		lookupCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		tunnelID, err = management.NamespaceTunnel(lookupCtx, opts.namespace, tunnelID)
		cancel()
		transport.CloseIdleConnections()
		if err != nil {
			common.LogError("namespace app publication failed", "error", err)
			os.Exit(1)
		}
		fmt.Fprintf(os.Stderr, "App URL: https://%s.%s\n", opts.tunnelID, strings.TrimPrefix(strings.ToLower(strings.TrimSuffix(opts.namespace, ".")), "*."))
	}

	// Get tunnel key from flag or env var
	if tunnelKey == "" {
		tunnelKey = cfg.WellKnownKey
		if tunnelKey == "" {
			common.LogError("tunnel key not provided - use --tunnel-key or set WELL_KNOWN_KEY env var")
			os.Exit(1)
		}
	}

	// Generate tunnel ID if not provided
	if tunnelID == "" {
		tunnelID = common.RandID(7)
	}

	// Normalize target URL
	normalizedTarget, err := normalizeTargetURL(target)
	if err != nil {
		common.LogError("invalid target", "error", err)
		os.Exit(1)
	}

	serveClient := &client.ServeClient{
		TunnelID:  tunnelID,
		TargetURL: normalizedTarget,
		Public:    opts.public, RequireSharing: true,
		ServerAddr:          cfg.ServerAddr,
		AuthToken:           token,
		Credentials:         credentials,
		TunnelKey:           tunnelKey,
		AllowedEmails:       allowedEmails,
		Insecure:            cfg.Insecure || *insecure,
		SkipLocalTLSVerify:  opts.skipLocalTLSVerify,
		RequireUpstreamAuth: opts.requireUpstreamAuth,
		WebSocket:           &opts.webSocket,
	}

	if opts.webhookProvider != "" {
		path, saveErr := client.SaveWebhookSecret(cfg.ServerAddr, tunnelID, opts.webhookProvider, client.WebhookAccountBinding(token), webhookSecret)
		if saveErr != nil {
			common.LogError("cannot store webhook endpoint secret")
			os.Exit(1)
		}
		serveClient.WebhookPolicy = &pb.WebhookPolicy{Provider: opts.webhookProvider, ToleranceSeconds: uint32(opts.webhookTolerance / time.Second)}
		serveClient.WebhookSecretPath = path
	}
	if opts.bearer {
		creator, identityErr := common.ExtractEmailFromJWT(token)
		if identityErr != nil && len(allowedEmails) == 0 {
			common.LogError("--bearer requires a tunn login token or an explicit --allow")
			os.Exit(1)
		}
		if creator != "" {
			serveClient.AllowedEmails = appendUniqueEmail(serveClient.AllowedEmails, creator)
		}
		endpointToken, digest, tokenErr := client.GenerateEndpointToken()
		if tokenErr != nil {
			common.LogError("failed to generate endpoint token", "error", tokenErr)
			os.Exit(1)
		}
		path, tokenErr := client.SaveEndpointToken(tunnelID, endpointToken)
		if tokenErr != nil {
			common.LogError("failed to store endpoint token", "error", tokenErr)
			os.Exit(1)
		}
		serveClient.AccessTokenSHA256 = digest
		serveClient.EndpointTokenPath = path
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if opts.expire > 0 {
		var stop context.CancelFunc
		ctx, stop = context.WithTimeout(ctx, opts.expire)
		defer stop()
	}
	if opts.qr {
		serveClient.OnRegistered = func(u string) {
			if err := hostmode.RenderQR(ctx, u, os.Stderr, ""); err != nil {
				common.LogError("QR rendering failed", "error", err)
			}
		}
	}
	if opts.inspect {
		inspector := client.NewInspectorWithBodyCapture(serveClient, opts.inspectBody)
		viewerURL, err := inspector.StartInspector(ctx)
		if err != nil {
			common.LogError("failed to start local inspector", "error", err)
			os.Exit(1)
		}
		serveClient.Inspector = inspector
		fmt.Fprintf(os.Stderr, "Local inspector: %s\n", viewerURL)
	}

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sigChan
		common.LogInfo("received shutdown signal")
		cancel()
	}()

	if err := serveClient.Run(ctx); err != nil && err != context.Canceled && err != context.DeadlineExceeded {
		exitIfLoginRequired(err)
		common.LogError("tunnel error", "error", err)
		os.Exit(1)
	}
}

func printServeUsage() {
	fmt.Fprintln(os.Stderr, `Usage: tunn serve [options] <port|host:port|url>
       tunn <target> [options]

Options:
  --id, --name, --subdomain NAME  Tunnel name (blank generates one)
  --namespace SUFFIX             Publish --name under a verified custom namespace
  --allow EMAILS                 Comma-separated email allow-list
  --bearer                       Enable endpoint tokens for HTTP and WebSockets
  --require-upstream-auth        Require application Authorization after tunn auth
  --verify-webhook PROVIDER      Stripe, GitHub, Slack, Shopify or hmac-sha256 (lowercase)
  --webhook-secret-file PATH     Private signing-secret file (mode 0600)
  --webhook-tolerance DURATION   Signed timestamp tolerance (default 5m; 1s to 1h)
  --ws-idle-timeout DURATION     WebSocket inactivity timeout (default 5m; 0 disables)
  --ws-keepalive DURATION        Ping interval (default 30s; 0 disables)
  --ws-max-message-size BYTES    Message limit across fragments (default 8388608)
  --inspect                     Open a local metadata inspector
  --inspect-body                Retain local bodies up to 64 KiB (requires --inspect)
  --skip-local-tls-verify        Skip local HTTPS certificate verification
  --secret SECRET               Self-hosted publisher secret (or TUNN_SECRET)
  --tunnel-key KEY               Tunnel creation authorization key`)
}

// normalizeTargetURL converts various input formats to a full URL
// Accepts: "8000", "localhost:8000", "http://localhost:8000"
// Always returns: "http://localhost:8000" format
func normalizeTargetURL(input string) (string, error) {
	if input == "" {
		return "", fmt.Errorf("empty target")
	}

	// If it's already a full URL, validate and return
	if strings.HasPrefix(input, "http://") || strings.HasPrefix(input, "https://") {
		return input, nil
	}

	// Check if it's "host:port" format
	if strings.Contains(input, ":") {
		return "http://" + input, nil
	}

	// Check if it's just a port number
	for _, char := range input {
		if char < '0' || char > '9' {
			return "", fmt.Errorf("invalid format: %s (expected port, host:port, or full URL)", input)
		}
	}

	// It's just a port number
	return "http://localhost:" + input, nil
}

func runMagicLink(args []string) {
	fs := flag.NewFlagSet("magic-link", flag.ExitOnError)
	secretFlag := fs.String("secret", "", "JWT signing secret (or set TUNN_JWT_SECRET env var)")
	domainFlag := fs.String("domain", "", "domain for full URL output (e.g., tunn.to)")
	expiryFlag := fs.Duration("expiry", 5*time.Minute, "token expiry duration")
	tokenOnlyFlag := fs.Bool("token-only", false, "output only the token, not the full URL")

	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, `tunn magic-link - generate a magic link token for email authentication

Usage:
  tunn magic-link [options] <email>

Examples:
  tunn magic-link alice@example.com                       # Token only (uses TUNN_JWT_SECRET)
  tunn magic-link --secret=mysecret alice@example.com     # With explicit secret
  tunn magic-link --domain=tunn.to alice@example.com      # Full URL output

Options:
`)
		fs.PrintDefaults()
	}

	// Separate flags from positional args
	var nonFlagArgs []string
	var flagArgs []string
	for _, arg := range args {
		if strings.HasPrefix(arg, "-") {
			flagArgs = append(flagArgs, arg)
		} else {
			nonFlagArgs = append(nonFlagArgs, arg)
		}
	}

	if err := fs.Parse(flagArgs); err != nil {
		os.Exit(2)
	}

	if len(nonFlagArgs) == 0 {
		common.LogError("email required: tunn magic-link <email>")
		fs.Usage()
		os.Exit(1)
	}

	email := strings.ToLower(strings.TrimSpace(nonFlagArgs[0]))
	if !strings.Contains(email, "@") {
		common.LogError("invalid email address", "email", email)
		os.Exit(1)
	}

	// Get secret from flag or env
	secret := *secretFlag
	if secret == "" {
		secret = os.Getenv("TUNN_JWT_SECRET")
	}
	if secret == "" {
		common.LogError("JWT secret required: use -secret flag or set TUNN_JWT_SECRET env var")
		os.Exit(1)
	}

	// Generate JTI for replay protection
	jtiBytes := make([]byte, 16)
	if _, err := rand.Read(jtiBytes); err != nil {
		common.LogError("failed to generate JTI", "error", err)
		os.Exit(1)
	}
	jti := hex.EncodeToString(jtiBytes)

	// Generate magic link token with JTI for replay protection
	claims := jwt.MapClaims{
		"jti":   jti,
		"email": email,
		"type":  "magic_link",
		"iat":   time.Now().Unix(),
		"exp":   time.Now().Add(*expiryFlag).Unix(),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString([]byte(secret))
	if err != nil {
		common.LogError("failed to sign token", "error", err)
		os.Exit(1)
	}

	// Output
	if *tokenOnlyFlag || *domainFlag == "" {
		fmt.Println(tokenString)
	} else {
		fmt.Printf("https://%s/auth/verify?token=%s\n", *domainFlag, tokenString)
	}
}
