// A local streamable HTTP MCP server using the SDK's default handler.
package main

import (
	"context"
	"flag"
	"log"
	"net/http"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

type echoInput struct {
	Message string `json:"message" jsonschema:"Message to echo"`
}

func main() {
	addr := flag.String("addr", "127.0.0.1:3000", "loopback listen address")
	flag.Parse()
	server := mcp.NewServer(&mcp.Implementation{Name: "tunn-echo-demo", Version: "1.0.0"}, nil)
	mcp.AddTool(server, &mcp.Tool{Name: "echo", Description: "Return your message."}, func(_ context.Context, _ *mcp.CallToolRequest, input echoInput) (*mcp.CallToolResult, any, error) {
		return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: input.Message}}}, nil, nil
	})
	handler := mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server { return server }, nil)
	mux := http.NewServeMux()
	mux.Handle("/mcp", handler)
	log.Fatal(http.ListenAndServe(*addr, mux))
}
