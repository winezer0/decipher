package main

import (
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/winezer0/decipher/sdk"
)

const (
	serverName            = "decipher"
	defaultRequestBytes   = 4 << 20
	defaultMaxListItems   = 10000
	defaultMaxValueBytes  = 64 << 10
	defaultConcurrentCall = 4
	remoteTokenError      = "DECIPHER_MCP_TOKEN must be set when listening on a non-local address"
	requestHeaderTimeout  = 5 * time.Second
	requestReadTimeout    = 30 * time.Second
	connectionIdleTimeout = 60 * time.Second
	shutdownTimeout       = 10 * time.Second
)

type serverConfig struct {
	BearerToken            string
	MaxRequestBodyBytes    int64
	MaxListItems           int
	MaxValueBytes          int
	MaxConcurrentToolCalls int
}

// defaultServerConfig returns bounded MCP server defaults.
func defaultServerConfig() serverConfig {
	return serverConfig{
		MaxRequestBodyBytes:    defaultRequestBytes,
		MaxListItems:           defaultMaxListItems,
		MaxValueBytes:          defaultMaxValueBytes,
		MaxConcurrentToolCalls: defaultConcurrentCall,
	}
}

// validate checks MCP resource limits before starting the server.
func (c serverConfig) validate() error {
	if c.MaxRequestBodyBytes <= 0 || c.MaxListItems <= 0 || c.MaxValueBytes <= 0 || c.MaxConcurrentToolCalls <= 0 {
		return errors.New("MCP resource limits must be greater than zero")
	}
	return nil
}

// newHandler creates the HTTP handler exposing the SDK as MCP tools.
func newHandler(client *sdk.Client, config serverConfig) http.Handler {
	limiter := newToolLimiter(config.MaxConcurrentToolCalls)
	limits := inputLimits{maxItems: config.MaxListItems, maxValueBytes: config.MaxValueBytes}
	server := mcp.NewServer(&mcp.Implementation{Name: serverName, Version: "1.0.0"}, nil)
	registerTools(server, client, limits, limiter)
	mcpHandler := mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server {
		return server
	}, &mcp.StreamableHTTPOptions{
		Stateless:           true,
		MaxRequestBodyBytes: config.MaxRequestBodyBytes,
	})
	mux := http.NewServeMux()
	mux.Handle("/mcp", bearerAuth(mcpHandler, config.BearerToken))
	return mux
}

// newHTTPServer creates an HTTP server with timeouts suitable for MCP requests.
func newHTTPServer(address string, handler http.Handler) *http.Server {
	return &http.Server{
		Addr:              address,
		Handler:           handler,
		ReadHeaderTimeout: requestHeaderTimeout,
		ReadTimeout:       requestReadTimeout,
		IdleTimeout:       connectionIdleTimeout,
		MaxHeaderBytes:    1 << 20,
	}
}

// bearerAuth protects an HTTP handler with a bearer token when one is configured.
func bearerAuth(next http.Handler, token string) http.Handler {
	if token == "" {
		return next
	}
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		parts := strings.Fields(request.Header.Get("Authorization"))
		valid := len(parts) == 2 && strings.EqualFold(parts[0], "Bearer") &&
			subtle.ConstantTimeCompare([]byte(parts[1]), []byte(token)) == 1
		if !valid {
			writer.Header().Set("WWW-Authenticate", "Bearer")
			http.Error(writer, "Unauthorized", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(writer, request)
	})
}

// requiresBearerToken reports whether an address can accept non-local connections.
func requiresBearerToken(address string) bool {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return true
	}
	if strings.EqualFold(host, "localhost") {
		return false
	}
	ipHost := strings.Split(host, "%")[0]
	ip := net.ParseIP(ipHost)
	return ip == nil || !ip.IsLoopback()
}

// validateListenSecurity requires a token for addresses reachable beyond localhost.
func validateListenSecurity(address, token string) error {
	if requiresBearerToken(address) && token == "" {
		return errors.New(remoteTokenError)
	}
	return nil
}

// serveHTTP serves until the context is cancelled, then gracefully shuts down.
func serveHTTP(ctx context.Context, server *http.Server, listener net.Listener) error {
	serveErrors := make(chan error, 1)
	go func() { serveErrors <- server.Serve(listener) }()
	select {
	case err := <-serveErrors:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	case <-ctx.Done():
		shutdownContext, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
		defer cancel()
		if err := server.Shutdown(shutdownContext); err != nil {
			_ = server.Close()
			return fmt.Errorf("shut down MCP HTTP server: %w", err)
		}
		err := <-serveErrors
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	}
}
