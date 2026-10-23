package main

import (
	"context"
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// TestInputLimits checks list and individual string boundaries.
func TestInputLimits(t *testing.T) {
	limits := inputLimits{maxItems: 2, maxValueBytes: 4}
	tests := []struct {
		name  string
		lists [][]string
		want  string
	}{
		{name: "within limits", lists: [][]string{{"a", "1234"}}},
		{name: "empty lists", lists: [][]string{{}}},
		{name: "too many items in one list", lists: [][]string{{"a", "b", "c"}}, want: "maximum of 2 list items"},
		{name: "too many items across lists", lists: [][]string{{"a"}, {"b"}, {"c"}}, want: "maximum of 2 list items"},
		{name: "string too large", lists: [][]string{{"12345"}}, want: "maximum of 4 bytes"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := limits.validate(test.lists...)
			if test.want == "" && err != nil {
				t.Fatal(err)
			}
			if test.want != "" && (err == nil || !strings.Contains(err.Error(), test.want)) {
				t.Fatalf("error = %v, want it to contain %q", err, test.want)
			}
		})
	}
}

// TestServerConfigValidation checks that invalid resource limits are rejected.
func TestServerConfigValidation(t *testing.T) {
	valid := defaultServerConfig()
	if err := valid.validate(); err != nil {
		t.Fatalf("default config invalid: %v", err)
	}
	tests := []struct {
		name   string
		update func(*serverConfig)
	}{
		{name: "request bytes", update: func(config *serverConfig) { config.MaxRequestBodyBytes = 0 }},
		{name: "list items", update: func(config *serverConfig) { config.MaxListItems = 0 }},
		{name: "value bytes", update: func(config *serverConfig) { config.MaxValueBytes = 0 }},
		{name: "concurrent calls", update: func(config *serverConfig) { config.MaxConcurrentToolCalls = 0 }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			config := defaultServerConfig()
			test.update(&config)
			if err := config.validate(); err == nil {
				t.Fatal("expected invalid config error")
			}
		})
	}
}

// TestToolLimiterRejectsConcurrentCalls verifies overload is rejected promptly.
func TestToolLimiterRejectsConcurrentCalls(t *testing.T) {
	limiter := newToolLimiter(1)
	started := make(chan struct{})
	release := make(chan struct{})
	handler := limitedTool(limiter, func(_ context.Context, _ *mcp.CallToolRequest, input string) (*mcp.CallToolResult, string, error) {
		close(started)
		<-release
		return nil, input, nil
	})
	finished := make(chan error, 1)
	go func() {
		_, _, err := handler(context.Background(), nil, "first")
		finished <- err
	}()
	<-started
	_, _, err := handler(context.Background(), nil, "second")
	if err == nil || err.Error() != concurrentLimitError {
		t.Fatalf("concurrent call error = %v, want %q", err, concurrentLimitError)
	}
	close(release)
	if err := <-finished; err != nil {
		t.Fatalf("first call returned error: %v", err)
	}
}
