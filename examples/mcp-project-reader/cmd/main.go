// The stdio operator entry point opens no listener. The worker compiles it only.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"

	reader "github.com/ehrlich-b/tunn/examples/mcp-project-reader"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func main() {
	root := flag.String("root", "", "absolute canonical fixture root (required)")
	flag.Parse()
	if flag.NArg() != 0 {
		fmt.Fprintln(os.Stderr, "project-reader: unexpected_argument")
		os.Exit(2)
	}
	r, err := reader.Open(*root)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	if r.Server().Run(ctx, &mcp.StdioTransport{}) != nil {
		fmt.Fprintln(os.Stderr, "project-reader: protocol_failed")
		os.Exit(1)
	}
}
