package main

import (
	"context"
	"crypto/md5"
	"encoding/base64"
	"encoding/hex"
	"net/http/httptest"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// TestMCPPerCallAffixes checks request-level affixes reach SDK operations.
func TestMCPPerCallAffixes(t *testing.T) {
	const plaintext = "hello"
	const secret = "salt"
	const algorithm = "md5($pass.$salt)"
	const passPrefix = "P-"
	const passSuffix = "-S"
	const saltPrefix = "X-"
	const saltSuffix = "-Y"
	digest := md5.Sum([]byte(passPrefix + plaintext + passSuffix + saltPrefix + secret + saltSuffix))
	wantHash := hex.EncodeToString(digest[:])

	server := httptest.NewServer(newTestHandler(t, defaultServerConfig()))
	t.Cleanup(server.Close)

	mcpClient := mcp.NewClient(&mcp.Implementation{Name: "affix-test", Version: "1.0.0"}, nil)
	session, err := mcpClient.Connect(context.Background(), &mcp.StreamableClientTransport{
		Endpoint: server.URL + "/mcp", DisableStandaloneSSE: true,
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = session.Close() })

	ctx := context.Background()
	encodedPlaintext := base64.StdEncoding.EncodeToString([]byte(passPrefix + plaintext + passSuffix))
	encrypted := callTool(t, ctx, session, "encrypt", map[string]any{
		"plaintexts": []string{plaintext}, "secrets": []string{secret}, "algorithms": []string{"base64($pass)"},
		"affixes": map[string]string{"pass_prefix": passPrefix, "pass_suffix": passSuffix, "salt_prefix": saltPrefix, "salt_suffix": saltSuffix},
	})
	assertToolSuccess(t, encrypted, `"hash":"`+encodedPlaintext+`"`)

	cracked := callTool(t, ctx, session, "crack", map[string]any{
		"targets": []string{wantHash}, "plaintexts": []string{plaintext},
		"secrets": []string{secret}, "algorithms": []string{algorithm},
		"affixes": map[string]string{"pass_prefix": passPrefix, "pass_suffix": passSuffix, "salt_prefix": saltPrefix, "salt_suffix": saltSuffix},
	})
	assertToolSuccess(t, cracked, `"plaintext":"`+passPrefix+plaintext+passSuffix+`"`)

	decrypted := callTool(t, ctx, session, "decrypt", map[string]any{
		"targets": []string{"Ls34Pql552iTH1xkO+dy1OWAQx0GdmK5"},
		"secrets": []string{"m"}, "algorithms": []string{"des_crmeb_admin"},
		"affixes": map[string]string{"salt_prefix": "ad", "salt_suffix": "in"},
	})
	assertToolSuccess(t, decrypted, `"plaintext":"Y9jmpE.7ERnid4BG"`)
}
