package client

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"sync"

	"github.com/ehrlich-b/tunn/internal/common"
	"github.com/ehrlich-b/tunn/internal/relaytransport"
)

// ConnectClient bridges a remote tunn CONNECT endpoint to a local TCP listener
// or a single stdio stream for SSH ProxyCommand.
type ConnectClient struct {
	EndpointURL string
	Token       string
	ListenAddr  string
	Insecure    bool
	Output      io.Writer
	HTTPClient  *http.Client // Optional embedded or test transport.
}

func (c *ConnectClient) Run(ctx context.Context) error {
	listenAddr := c.ListenAddr
	if listenAddr == "" {
		listenAddr = "127.0.0.1:0"
	}
	listener, err := net.Listen("tcp", listenAddr)
	if err != nil {
		return fmt.Errorf("listen for local TCP connections: %w", err)
	}
	defer func() { _ = listener.Close() }()

	output := c.Output
	if output == nil {
		output = os.Stdout
	}
	_, _ = fmt.Fprintf(output, "tcp://%s -> %s\n", listener.Addr(), c.EndpointURL)

	httpClient, cleanup := c.httpClient()
	defer cleanup()

	stop := context.AfterFunc(ctx, func() { _ = listener.Close() })
	defer stop()

	var connections sync.WaitGroup
	defer connections.Wait()
	for {
		connection, err := listener.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			return fmt.Errorf("accept local TCP connection: %w", err)
		}
		connections.Add(1)
		go func() {
			defer connections.Done()
			if err := c.handleConnection(ctx, httpClient, connection); err != nil && ctx.Err() == nil {
				_, _ = fmt.Fprintf(output, "connection failed: %v\n", err)
			}
		}()
	}
}

func (c *ConnectClient) handleConnection(ctx context.Context, httpClient *http.Client, local net.Conn) error {
	return c.handleStream(ctx, httpClient, local, local)
}

// RunStdio opens exactly one connection without a listener or status output.
// EOF on input half-closes the upload while the response remains readable.
// The streams are closed on return or cancellation to unblock pending I/O.
func (c *ConnectClient) RunStdio(ctx context.Context, input io.ReadCloser, output io.WriteCloser) error {
	httpClient, cleanup := c.httpClient()
	defer cleanup()
	return c.handleStream(ctx, httpClient, input, output)
}

func (c *ConnectClient) httpClient() (*http.Client, func()) {
	if c.HTTPClient != nil {
		return c.HTTPClient, func() {}
	}
	transport := relaytransport.Transport(c.Insecure)
	return &http.Client{Transport: transport}, transport.CloseIdleConnections
}

func (c *ConnectClient) handleStream(ctx context.Context, httpClient *http.Client, input io.ReadCloser, output io.WriteCloser) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	closeStreams := func() {
		_ = input.Close()
		_ = output.Close()
	}
	defer closeStreams()
	stop := context.AfterFunc(ctx, closeStreams)
	defer stop()
	requestReader, requestWriter := io.Pipe()
	defer func() { _ = requestReader.Close() }()

	request, err := http.NewRequestWithContext(ctx, http.MethodConnect, c.EndpointURL, requestReader)
	if err != nil {
		return fmt.Errorf("create CONNECT request: %w", err)
	}
	request.ContentLength = -1
	request.Header.Set(common.TCPConnectHeader, common.TCPConnectValue)
	if c.Token != "" {
		request.Header.Set("Tunn-Authorization", "Bearer "+c.Token)
	}

	uploadDone := make(chan error, 1)
	uploadJoined := false
	go func() {
		_, copyErr := io.Copy(requestWriter, input)
		_ = requestWriter.CloseWithError(copyErr)
		uploadDone <- copyErr
	}()
	defer func() {
		_ = requestWriter.Close()
		_ = input.Close()
		if !uploadJoined {
			<-uploadDone
		}
	}()

	copyClient := *httpClient
	copyClient.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	response, err := copyClient.Do(request)
	if err != nil {
		_ = requestWriter.CloseWithError(err)
		return fmt.Errorf("open remote TCP endpoint: %w", err)
	}
	defer func() { _ = response.Body.Close() }()
	stopResponse := context.AfterFunc(ctx, func() { _ = response.Body.Close() })
	defer stopResponse()
	if response.StatusCode != http.StatusOK {
		message, _ := io.ReadAll(io.LimitReader(response.Body, 4096))
		return fmt.Errorf("remote endpoint returned %s: %s", response.Status, message)
	}

	_, downloadErr := io.Copy(output, response.Body)
	if halfCloser, ok := output.(interface{ CloseWrite() error }); ok {
		_ = halfCloser.CloseWrite()
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if reason := response.Trailer.Get("Tunn-Limit-Reason"); reason != "" {
		return fmt.Errorf("remote TCP endpoint stopped: %s", reason)
	}
	if downloadErr != nil {
		return fmt.Errorf("read remote TCP endpoint: %w", downloadErr)
	}

	select {
	case uploadErr := <-uploadDone:
		uploadJoined = true
		if uploadErr != nil {
			return fmt.Errorf("write remote TCP endpoint: %w", uploadErr)
		}
	default:
	}
	return nil
}
