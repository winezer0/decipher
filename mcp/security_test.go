package main

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// TestRequiresBearerToken checks local and remotely reachable bind addresses.
func TestRequiresBearerToken(t *testing.T) {
	tests := []struct {
		address string
		want    bool
	}{
		{address: "127.0.0.1:8080", want: false},
		{address: "[::1]:8080", want: false},
		{address: "localhost:8080", want: false},
		{address: "0.0.0.0:8080", want: true},
		{address: ":8080", want: true},
		{address: "192.0.2.1:8080", want: true},
		{address: "invalid", want: true},
	}
	for _, test := range tests {
		t.Run(test.address, func(t *testing.T) {
			if got := requiresBearerToken(test.address); got != test.want {
				t.Fatalf("requiresBearerToken(%q) = %t, want %t", test.address, got, test.want)
			}
		})
	}
}

// TestValidateListenSecurity checks remote binds require a configured token.
func TestValidateListenSecurity(t *testing.T) {
	tests := []struct {
		name    string
		address string
		token   string
		wantErr bool
	}{
		{name: "local without token", address: "127.0.0.1:8080"},
		{name: "remote with token", address: "0.0.0.0:8080", token: "secret"},
		{name: "remote without token", address: "0.0.0.0:8080", wantErr: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := validateListenSecurity(test.address, test.token)
			if (err != nil) != test.wantErr {
				t.Fatalf("validateListenSecurity() error = %v, want error %t", err, test.wantErr)
			}
		})
	}
}

// TestBearerAuth checks missing, invalid, and valid authorization headers.
func TestBearerAuth(t *testing.T) {
	handler := bearerAuth(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writer.WriteHeader(http.StatusNoContent)
	}), "test-token")
	tests := []struct {
		name       string
		header     string
		wantStatus int
	}{
		{name: "missing", wantStatus: http.StatusUnauthorized},
		{name: "wrong token", header: "Bearer wrong", wantStatus: http.StatusUnauthorized},
		{name: "invalid scheme", header: "Basic test-token", wantStatus: http.StatusUnauthorized},
		{name: "valid token", header: "Bearer test-token", wantStatus: http.StatusNoContent},
		{name: "case insensitive scheme", header: "bearer test-token", wantStatus: http.StatusNoContent},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodGet, "/mcp", nil)
			request.Header.Set("Authorization", test.header)
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			if response.Code != test.wantStatus {
				t.Fatalf("status = %d, want %d", response.Code, test.wantStatus)
			}
		})
	}
}

// TestBearerAuthMCPHandshake verifies authorization works with the MCP client transport.
func TestBearerAuthMCPHandshake(t *testing.T) {
	config := defaultServerConfig()
	config.BearerToken = "integration-secret"
	server := httptest.NewServer(newTestHandler(t, config))
	t.Cleanup(server.Close)

	unauthorized, err := http.Get(server.URL + "/mcp")
	if err != nil {
		t.Fatal(err)
	}
	_ = unauthorized.Body.Close()
	if unauthorized.StatusCode != http.StatusUnauthorized {
		t.Fatalf("unauthorized status = %d, want %d", unauthorized.StatusCode, http.StatusUnauthorized)
	}

	client := mcp.NewClient(&mcp.Implementation{Name: "token-test", Version: "1.0.0"}, nil)
	transport := &mcp.StreamableClientTransport{
		Endpoint: server.URL + "/mcp",
		HTTPClient: &http.Client{Transport: bearerRoundTripper{
			token: config.BearerToken,
			base:  http.DefaultTransport,
		}},
		DisableStandaloneSSE: true,
	}
	session, err := client.Connect(context.Background(), transport, nil)
	if err != nil {
		t.Fatalf("connect with bearer token: %v", err)
	}
	t.Cleanup(func() { _ = session.Close() })
	listed, err := session.ListTools(context.Background(), &mcp.ListToolsParams{})
	if err != nil {
		t.Fatalf("list tools with bearer token: %v", err)
	}
	if len(listed.Tools) != 9 {
		t.Fatalf("tool count = %d, want 9", len(listed.Tools))
	}
}

type bearerRoundTripper struct {
	token string
	base  http.RoundTripper
}

// RoundTrip adds the configured bearer token to an outgoing HTTP request.
func (t bearerRoundTripper) RoundTrip(request *http.Request) (*http.Response, error) {
	copy := request.Clone(request.Context())
	copy.Header.Set("Authorization", "Bearer "+t.token)
	return t.base.RoundTrip(copy)
}

// TestHTTPBodyLimit rejects request bodies larger than the configured maximum.
func TestHTTPBodyLimit(t *testing.T) {
	config := defaultServerConfig()
	config.MaxRequestBodyBytes = 32
	handler := newTestHandler(t, config)
	request := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(strings.Repeat("x", 128)))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Accept", "application/json, text/event-stream")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusRequestEntityTooLarge)
	}
}

// TestHTTPServerLifecycle checks timeout configuration and graceful shutdown.
func TestHTTPServerLifecycle(t *testing.T) {
	server := newHTTPServer("", http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writer.WriteHeader(http.StatusOK)
	}))
	if server.ReadHeaderTimeout <= 0 || server.ReadTimeout <= 0 || server.IdleTimeout <= 0 || server.MaxHeaderBytes <= 0 {
		t.Fatalf("HTTP timeouts and header limit must be configured: %+v", server)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	finished := make(chan error, 1)
	go func() { finished <- serveHTTP(ctx, server, listener) }()

	response, err := http.Get("http://" + listener.Addr().String())
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	_ = response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("response status = %d, want %d", response.StatusCode, http.StatusOK)
	}
	cancel()
	select {
	case err := <-finished:
		if err != nil {
			t.Fatalf("serveHTTP returned error: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("server did not stop after context cancellation")
	}
}
