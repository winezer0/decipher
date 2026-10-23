package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/winezer0/decipher/sdk"
)

// TestHTTPMCPExposesSDKTools checks all SDK tools through the HTTP transport.
func TestHTTPMCPExposesSDKTools(t *testing.T) {
	session := newTestSession(t)
	ctx := context.Background()

	listed, err := session.ListTools(ctx, &mcp.ListToolsParams{})
	if err != nil {
		t.Fatal(err)
	}
	wantTools := []string{
		"add_plaintexts", "add_secrets", "crack", "crack_with_builtin_dictionaries", "decrypt",
		"encrypt", "identify", "init_builtin_dictionaries", "list_algorithms",
	}
	gotTools := make([]string, 0, len(listed.Tools))
	for _, tool := range listed.Tools {
		gotTools = append(gotTools, tool.Name)
	}
	slices.Sort(gotTools)
	if !slices.Equal(gotTools, wantTools) {
		t.Fatalf("tools = %v, want %v", gotTools, wantTools)
	}

	calls := []struct {
		name     string
		args     map[string]any
		contains string
	}{
		{name: "list_algorithms", args: map[string]any{}, contains: `"name":"md5($pass)"`},
		{name: "identify", args: map[string]any{"hashes": []string{"5d41402abc4b2a76b9719d911017c592"}}, contains: `"hash":"5d41402abc4b2a76b9719d911017c592"`},
		{name: "encrypt", args: map[string]any{"plaintexts": []string{"hello"}, "algorithms": []string{"base64($pass)"}}, contains: `"hash":"aGVsbG8="`},
		{name: "crack", args: map[string]any{"targets": []string{"5d41402abc4b2a76b9719d911017c592"}, "plaintexts": []string{"hello"}, "algorithms": []string{"md5($pass)"}}, contains: `"plaintext":"hello"`},
		{name: "decrypt", args: map[string]any{"targets": []string{"aGVsbG8="}, "algorithms": []string{"base64($pass)"}}, contains: `"plaintext":"hello"`},
		{name: "init_builtin_dictionaries", args: map[string]any{}, contains: `"ok":true`},
		{name: "add_plaintexts", args: map[string]any{"plaintexts": []string{"hello"}}, contains: `"ok":true`},
		{name: "add_secrets", args: map[string]any{"secrets": []string{"salt"}}, contains: `"ok":true`},
		{name: "crack_with_builtin_dictionaries", args: map[string]any{"targets": []string{"5d41402abc4b2a76b9719d911017c592"}, "algorithms": []string{"md5($pass)"}}, contains: `"plaintext":"hello"`},
	}
	for _, test := range calls {
		t.Run(test.name, func(t *testing.T) {
			result := callTool(t, ctx, session, test.name, test.args)
			assertToolSuccess(t, result, test.contains)
		})
	}
}

// TestHTTPMCPToolValidation checks invalid and empty list arguments over HTTP.
func TestHTTPMCPToolValidation(t *testing.T) {
	session := newTestSession(t)
	ctx := context.Background()

	t.Run("missing required plaintexts", func(t *testing.T) {
		result := callTool(t, ctx, session, "encrypt", map[string]any{"algorithms": []string{"base64($pass)"}})
		assertToolError(t, result, "plaintexts")
	})
	t.Run("unknown algorithm", func(t *testing.T) {
		result := callTool(t, ctx, session, "crack", map[string]any{
			"targets": []string{"abc"}, "plaintexts": []string{"hello"}, "algorithms": []string{"unknown-algorithm"},
		})
		assertToolError(t, result, "unknown algorithm")
	})
	t.Run("empty identify list", func(t *testing.T) {
		result := callTool(t, ctx, session, "identify", map[string]any{"hashes": []string{}})
		assertToolSuccess(t, result, `[]`)
	})
	t.Run("empty dictionary append", func(t *testing.T) {
		result := callTool(t, ctx, session, "add_plaintexts", map[string]any{"plaintexts": []string{}})
		assertToolSuccess(t, result, `"ok":true`)
	})
}

// TestHTTPMCPResourceLimits checks MCP tool list and value limits over HTTP.
func TestHTTPMCPResourceLimits(t *testing.T) {
	config := defaultServerConfig()
	config.MaxListItems = 1
	config.MaxValueBytes = 4
	session := newTestSessionWithConfig(t, config)
	ctx := context.Background()

	tests := []struct {
		name     string
		hashes   []string
		contains string
	}{
		{name: "too many values", hashes: []string{"a", "b"}, contains: "maximum of 1 list items"},
		{name: "value too large", hashes: []string{"12345"}, contains: "maximum of 4 bytes"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result := callTool(t, ctx, session, "identify", map[string]any{"hashes": test.hashes})
			assertToolError(t, result, test.contains)
		})
	}
	t.Run("affix value too large", func(t *testing.T) {
		result := callTool(t, ctx, session, "encrypt", map[string]any{
			"plaintexts": []string{"a"},
			"affixes":    map[string]string{"pass_prefix": "12345"},
		})
		assertToolError(t, result, "maximum of 4 bytes")
	})
}

// newTestSession starts an isolated HTTP MCP server for a test.
func newTestSession(t *testing.T) *mcp.ClientSession {
	return newTestSessionWithConfig(t, defaultServerConfig())
}

// newTestSessionWithConfig starts an isolated MCP session with custom limits.
func newTestSessionWithConfig(t *testing.T, config serverConfig) *mcp.ClientSession {
	t.Helper()
	server := httptest.NewServer(newTestHandler(t, config))
	t.Cleanup(server.Close)

	ctx := context.Background()
	mcpClient := mcp.NewClient(&mcp.Implementation{Name: "decipher-test", Version: "1.0.0"}, nil)
	session, err := mcpClient.Connect(ctx, &mcp.StreamableClientTransport{Endpoint: server.URL + "/mcp"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = session.Close() })
	return session
}

// newTestHandler creates an MCP handler backed by test-only SDK directories.
func newTestHandler(t *testing.T, config serverConfig) http.Handler {
	t.Helper()
	root := t.TempDir()
	client, err := sdk.NewClient(sdk.Config{
		Workers: 1, DataDir: filepath.Join(root, "data"), RunCacheDir: filepath.Join(root, "cache"),
	})
	if err != nil {
		t.Fatal(err)
	}
	return newHandler(client, config)
}

// callTool invokes one tool and fails the test on transport errors.
func callTool(t *testing.T, ctx context.Context, session *mcp.ClientSession, name string, args map[string]any) *mcp.CallToolResult {
	t.Helper()
	result, err := session.CallTool(ctx, &mcp.CallToolParams{Name: name, Arguments: args})
	if err != nil {
		t.Fatalf("call %s: %v", name, err)
	}
	return result
}

// assertToolSuccess checks the structured tool result contains expected JSON.
func assertToolSuccess(t *testing.T, result *mcp.CallToolResult, contains string) {
	t.Helper()
	if result.IsError {
		t.Fatalf("unexpected tool error: %s", encodeContent(t, result.Content))
	}
	encoded, err := json.Marshal(result.StructuredContent)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(encoded), contains) {
		t.Fatalf("result %s does not contain %q", encoded, contains)
	}
}

// assertToolError checks the tool reports an expected error.
func assertToolError(t *testing.T, result *mcp.CallToolResult, contains string) {
	t.Helper()
	if !result.IsError {
		t.Fatalf("expected tool error, got %s", encodeContent(t, result.Content))
	}
	encoded := encodeContent(t, result.Content)
	if !strings.Contains(encoded, contains) {
		t.Fatalf("error %s does not contain %q", encoded, contains)
	}
}

// encodeContent marshals MCP content for test failure messages.
func encodeContent(t *testing.T, content any) string {
	t.Helper()
	encoded, err := json.Marshal(content)
	if err != nil {
		t.Fatal(err)
	}
	return string(encoded)
}
