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
	"github.com/ehrlich-b/tunn/internal/terminal"
	pb "github.com/ehrlich-b/tunn/pkg/proto/tunnelv1"
	"github.com/golang-jwt/jwt/v4"
	"github.com/joho/godotenv"
)

// Global flags (parsed before subcommand)
var (
	verbosity   = flag.String("verbosity", "request", "log level: none, error, request, trace")
	insecure    = flag.Bool("insecure", false, "skip TLS verification for proxy gRPC connection (insecure)")
	dev         = flag.Bool("dev", false, "use development configuration (or set TUNN_ENV=dev)")
	showVersion = flag.Bool("version", false, "print the build version and exit")

	// Hidden flag for server operators
	mode = flag.String("mode", "", "internal: host mode for server operators")

	// Host mode flags
	domain   = flag.String("domain", "tunn.to", "public apex domain")
	certFile = flag.String("cert", "/app/certs/fullchain.pem", "TLS certificate file (host mode)")
	keyFile  = flag.String("key", "/app/certs/privkey.pem", "TLS private key file (host mode)")
)

func main() {
	// Custom usage message
	flag.Usage = func() { printHelp(os.Stderr) }

	// Parse global flags first, but stop at first non-flag
	flag.Parse()
	args := flag.Args()
	if *showVersion || (len(args) > 0 && args[0] == "version") {
		if (*showVersion && len(args) != 0) || (!*showVersion && len(args) != 1) {
			fmt.Fprintln(os.Stderr, "Usage: tunn --version | tunn version")
			os.Exit(2)
		}
		fmt.Println("tunn", version)
		return
	}

	// Version queries need neither configuration nor credentials.
	_ = godotenv.Load()
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
		firstRun(os.Stdout)
		return
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
		if len(args) > 1 {
			if len(args) == 2 && (args[1] == "--help" || args[1] == "-h") {
				fmt.Fprintln(os.Stdout, "Usage: tunn login\n\nOpen your browser to sign in, then run\ntunn 3000")
				return
			}
			reportCLIError("Invalid sign-in command", "Login takes no options", "tunn login", false)
			os.Exit(1)
		}
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
		if errors.Is(err, flag.ErrHelp) {
			printRawHelp(os.Stderr, "tcp")
			return
		}
		common.LogError("invalid TCP endpoint", "error", err)
		printRawHelp(os.Stderr, "tcp")
		os.Exit(1)
	}
	runRawPublisher(opts, "tcp", "tcp")
}

func runUnix(args []string) {
	opts, err := parseUnixFlags(args)
	if err != nil {
		if errors.Is(err, flag.ErrHelp) {
			printRawHelp(os.Stderr, "unix")
			return
		}
		common.LogError("invalid Unix endpoint", "error", err)
		printRawHelp(os.Stderr, "unix")
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
		if errors.Is(err, flag.ErrHelp) {
			printRawHelp(os.Stderr, "connect")
			return
		}
		common.LogError("invalid connect command", "error", err)
		printRawHelp(os.Stderr, "connect")
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
	qr, public, jsonOutput             bool
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
	return &serveCommandOptions{webhookProvider: o.WebhookProvider, webhookSecretFile: o.WebhookSecretFile, webhookTolerance: o.WebhookTolerance, target: o.Target, tunnelID: o.Name, namespace: o.Namespace, allowedEmails: o.AllowedEmails, tunnelKey: o.TunnelKey, clientSecret: o.Secret, skipLocalTLSVerify: o.SkipLocalTLSVerify, inspect: o.Inspect, inspectBody: o.InspectBody, bearer: o.Bearer, requireUpstreamAuth: o.RequireUpstreamAuth, webSocket: o.WebSocket, expire: o.Expire, qr: o.QR, public: o.Public, jsonOutput: o.JSON}, nil
}

func runLogin() {
	if !commonTrace() {
		common.SetLogLevel(common.LogLevelError)
	}
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

	if err := loginClient.Run(ctx); err != nil && !errors.Is(err, context.Canceled) {
		reportCLIError("Sign-in failed", "Check connectivity, then retry", "tunn login", false)
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
		reportCLIError("Invalid HTTP command", terminal.Safe(err.Error()), "tunn http --help", jsonRequested(args))
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
	normalizedTarget, err := normalizeTargetURL(target)
	if err != nil {
		reportCLIError("Invalid local app address", "Use a port, host:port or HTTP URL", "tunn http --help", opts.jsonOutput)
		os.Exit(1)
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	output := terminal.New(os.Stdout, os.Stderr, opts.jsonOutput)

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
			if ctx.Err() != nil {
				output.State("stopped", "Canceled", "", "", 0)
				return
			}
			if client.RetryableCredentialError(err) {
				output.State("offline", "Cannot reach tunn", "Sign-in renewal failed. Check your connection, then run it again.", "", 0)
			} else {
				output.State("auth_expired", "Sign in to start a tunnel", "", "tunn login", 0)
			}
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

	serveClient := &client.ServeClient{
		ValidatePublicURL: validateCLIURL,
		TunnelID:          tunnelID,
		TargetURL:         normalizedTarget,
		Public:            opts.public, RequireSharing: true,
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

	attachCLI(ctx, serveClient, output, opts.inspect)
	runErr := serveClient.Run(ctx)
	if !stoppedNormally(runErr) {
		showTunnelError(output, runErr, cfg.ServerAddr)
		os.Exit(1)
	}
	output.State("stopped", "Tunnel stopped", "", "", 0)
	output.Summary()
}

func printServeUsage() {
	fmt.Fprintln(os.Stderr, `Usage: tunn serve [options] <port|host:port|url>
       tunn <target> [options]

Private by default. Use --public to let anyone with the link open it.

Options:
  --public                       Anyone with the link
  --json                         Request events as JSON lines
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
	candidate := input
	if !strings.HasPrefix(input, "http://") && !strings.HasPrefix(input, "https://") {
		if strings.Contains(input, ":") {
			candidate = "http://" + input
		} else {
			if _, err := strconv.ParseUint(input, 10, 16); err != nil {
				return "", fmt.Errorf("use a port, host:port or HTTP URL")
			}
			candidate = "http://localhost:" + input
		}
	}
	u, err := url.Parse(candidate)
	if err != nil || u.Hostname() == "" || u.Fragment != "" || (u.Scheme != "http" && u.Scheme != "https") {
		return "", fmt.Errorf("invalid HTTP address")
	}
	if port := u.Port(); port != "" {
		n, err := strconv.ParseUint(port, 10, 16)
		if err != nil || n == 0 {
			return "", fmt.Errorf("port must be between 1 and 65535")
		}
	}
	return candidate, nil
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
