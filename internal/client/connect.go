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
	Credentials *CredentialManager
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
	return c.connectStreams(ctx, httpClient, local, local)
}

// RunStdio bridges an SSH ProxyCommand without writing status text to stdout.
func (c *ConnectClient) RunStdio(ctx context.Context, input io.Reader, output io.Writer) error {
	transport := relaytransport.Transport(c.Insecure)
	defer transport.CloseIdleConnections()
	return c.connectStreams(ctx, &http.Client{Transport: transport}, input, output)
}

func (c *ConnectClient) connectStreams(ctx context.Context, httpClient *http.Client, input io.Reader, output io.Writer) error {
	token := c.Token
	var response *http.Response
	var requestReader *io.PipeReader
	var requestWriter *io.PipeWriter
	copyClient := *httpClient
	copyClient.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	for attempt := 0; attempt < 2; attempt++ {
		if c.Credentials != nil {
			var err error
			token, err = c.Credentials.Token(ctx, attempt == 1)
			if err != nil {
				return fmt.Errorf("CONNECT authentication renewal: %w", err)
			}
		}
		requestReader, requestWriter = io.Pipe()
		request, err := http.NewRequestWithContext(ctx, http.MethodConnect, c.EndpointURL, requestReader)
		if err != nil {
			requestReader.Close()
			requestWriter.Close()
			return fmt.Errorf("create CONNECT request: %w", err)
		}
		request.ContentLength = -1
		request.Header.Set(common.TCPConnectHeader, common.TCPConnectValue)
		if token != "" {
			request.Header.Set("Tunn-Authorization", "Bearer "+token)
		}
		response, err = copyClient.Do(request)
		if err != nil {
			requestReader.Close()
			requestWriter.Close()
			return fmt.Errorf("open remote TCP endpoint: %w", err)
		}
		if response.StatusCode == http.StatusOK {
			break
		}
		response.Body.Close()
		requestReader.Close()
		requestWriter.Close()
		if response.StatusCode == http.StatusUnauthorized && c.Credentials != nil && attempt == 0 {
			continue
		}
		return fmt.Errorf("remote endpoint returned %s; check access or run tunn login for account access", response.Status)
	}
	defer response.Body.Close()
	defer requestReader.Close()
	defer requestWriter.Close()
	uploadDone := make(chan error, 1)
	go func() {
		_, err := io.Copy(requestWriter, input)
		_ = requestWriter.CloseWithError(err)
		uploadDone <- err
	}()
	_, downloadErr := io.Copy(output, response.Body)
	if halfCloser, ok := output.(interface{ CloseWrite() error }); ok {
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
