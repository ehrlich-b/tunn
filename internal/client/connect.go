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

// ConnectClient turns a remote tunn CONNECT endpoint into a local TCP
// listener. Applications connect to ListenAddr and remain unaware of tunn.
type ConnectClient struct {
	EndpointURL string
	Token       string
	ListenAddr  string
	Insecure    bool
	Output      io.Writer
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

	transport := relaytransport.Transport(c.Insecure)
	defer transport.CloseIdleConnections()
	httpClient := &http.Client{Transport: transport}

	go func() {
		<-ctx.Done()
		_ = listener.Close()
	}()

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
	defer func() { _ = local.Close() }()
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
	go func() {
		_, copyErr := io.Copy(requestWriter, local)
		_ = requestWriter.CloseWithError(copyErr)
		uploadDone <- copyErr
	}()

	copyClient := *httpClient
	copyClient.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	response, err := copyClient.Do(request)
	if err != nil {
		_ = requestWriter.CloseWithError(err)
		return fmt.Errorf("open remote TCP endpoint: %w", err)
	}
	defer func() { _ = response.Body.Close() }()
	if response.StatusCode != http.StatusOK {
		message, _ := io.ReadAll(io.LimitReader(response.Body, 4096))
		return fmt.Errorf("remote endpoint returned %s: %s", response.Status, message)
	}

	_, downloadErr := io.Copy(local, response.Body)
	if halfCloser, ok := local.(interface{ CloseWrite() error }); ok {
		_ = halfCloser.CloseWrite()
	}
	if reason := response.Trailer.Get("Tunn-Limit-Reason"); reason != "" {
		return fmt.Errorf("remote TCP endpoint stopped: %s", reason)
	}
	if downloadErr != nil {
		return fmt.Errorf("read remote TCP endpoint: %w", downloadErr)
	}

	select {
	case uploadErr := <-uploadDone:
		if uploadErr != nil {
			return fmt.Errorf("write remote TCP endpoint: %w", uploadErr)
		}
	default:
	}
	return nil
}
