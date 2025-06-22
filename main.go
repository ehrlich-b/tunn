package main

import (
	"flag"
	"os"

	"github.com/ehrlich-b/tunn/internal/client"
	"github.com/ehrlich-b/tunn/internal/common"
	"github.com/ehrlich-b/tunn/internal/host"
)

var (
	mode      = flag.String("mode", "client", "host | client")
	to        = flag.String("to", "http://127.0.0.1:8000", "URL to forward to")
	id        = flag.String("id", "", "tunnel ID (client); blank → random")
	domain    = flag.String("domain", "tunn.to", "public apex domain")
	verbosity = flag.String("verbosity", "error", "log level: none, error, request, trace")
)

func main() {
	flag.Parse()

	// Setup logging
	logLevel := common.ParseLogLevel(*verbosity)
	common.SetLogLevel(logLevel)
	
	token := os.Getenv("TOKEN")
	if token != "" {
		common.LogInfo("using token from environment variable")
	} else {
		common.LogError("TOKEN environment variable not set")
		os.Exit(1)
	}

	switch *mode {
	case "host":
		server := &host.Server{
			Domain: *domain,
			Token:  token,
		}
		server.Run()
	case "client":
		client := &client.Client{
			ID:     *id,
			To:     *to,
			Domain: *domain,
			Token:  token,
		}
		client.Run()
	default:
		client := &client.Client{
			ID:     *id,
			To:     *to,
			Domain: *domain,
			Token:  token,
		}
		client.Run()
	}
}
