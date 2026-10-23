package main

import (
	"context"
	"flag"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"

	"github.com/winezer0/decipher/sdk"
)

const bearerTokenEnv = "DECIPHER_MCP_TOKEN"

func main() {
	address := flag.String("addr", "127.0.0.1:8080", "HTTP listen address")
	dataDir := flag.String("data-dir", "", "SDK dictionary data directory")
	cacheDir := flag.String("cache-dir", "", "SDK run cache directory")
	workers := flag.Int("workers", 0, "cracking worker count")
	maxBody := flag.Int64("max-request-body-bytes", defaultRequestBytes, "maximum MCP request body size")
	maxItems := flag.Int("max-list-items", defaultMaxListItems, "maximum total values across lists in one tool call")
	maxValueBytes := flag.Int("max-value-bytes", defaultMaxValueBytes, "maximum byte length of each input string")
	maxConcurrent := flag.Int("max-concurrent-calls", defaultConcurrentCall, "maximum concurrent MCP tool calls")
	flag.Parse()

	config := defaultServerConfig()
	config.BearerToken = os.Getenv(bearerTokenEnv)
	config.MaxRequestBodyBytes = *maxBody
	config.MaxListItems = *maxItems
	config.MaxValueBytes = *maxValueBytes
	config.MaxConcurrentToolCalls = *maxConcurrent
	if err := config.validate(); err != nil {
		log.Fatal(err)
	}
	if err := validateListenSecurity(*address, config.BearerToken); err != nil {
		log.Fatal(err)
	}

	client, err := sdk.NewClient(sdk.Config{
		Workers: *workers, DataDir: *dataDir, RunCacheDir: *cacheDir,
	})
	if err != nil {
		log.Fatal(err)
	}
	listener, err := net.Listen("tcp", *address)
	if err != nil {
		log.Fatal(err)
	}
	server := newHTTPServer(*address, newHandler(client, config))
	log.Printf("MCP server listening on %s/mcp", *address)
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := serveHTTP(ctx, server, listener); err != nil {
		log.Fatal(err)
	}
}
