package main

import (
	"context"
	"errors"
	"fmt"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

const concurrentLimitError = "concurrent MCP tool call limit reached"

type inputLimits struct {
	maxItems      int
	maxValueBytes int
}

type toolLimiter struct {
	slots chan struct{}
}

// newToolLimiter creates a non-blocking limiter for SDK tool calls.
func newToolLimiter(limit int) *toolLimiter {
	return &toolLimiter{slots: make(chan struct{}, limit)}
}

// validate checks list counts and individual string sizes.
func (l inputLimits) validate(lists ...[]string) error {
	itemCount := 0
	for _, values := range lists {
		if len(values) > l.maxItems-itemCount {
			return fmt.Errorf("tool input exceeds the maximum of %d list items", l.maxItems)
		}
		itemCount += len(values)
		for _, value := range values {
			if len(value) > l.maxValueBytes {
				return fmt.Errorf("value exceeds the maximum of %d bytes", l.maxValueBytes)
			}
		}
	}
	return nil
}

// validateValues checks scalar string options without counting them as list items.
func (l inputLimits) validateValues(values ...string) error {
	for _, value := range values {
		if len(value) > l.maxValueBytes {
			return fmt.Errorf("value exceeds the maximum of %d bytes", l.maxValueBytes)
		}
	}
	return nil
}

// limitedTool wraps an MCP tool handler with the shared concurrency limit.
func limitedTool[In, Out any](limiter *toolLimiter, handler mcp.ToolHandlerFor[In, Out]) mcp.ToolHandlerFor[In, Out] {
	return func(ctx context.Context, request *mcp.CallToolRequest, input In) (*mcp.CallToolResult, Out, error) {
		select {
		case limiter.slots <- struct{}{}:
			defer func() { <-limiter.slots }()
			return handler(ctx, request, input)
		default:
			var zero Out
			return nil, zero, errors.New(concurrentLimitError)
		}
	}
}
