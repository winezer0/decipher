package main

import (
	"context"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/winezer0/decipher/sdk"
)

type identifyInput struct {
	Hashes []string `json:"hashes" jsonschema:"Hash strings to identify"`
}

type addPlaintextsInput struct {
	Plaintexts []string `json:"plaintexts" jsonschema:"Plaintext values to append"`
}

type addSecretsInput struct {
	Secrets []string `json:"secrets" jsonschema:"Secret values to append"`
}

type encryptInput struct {
	Plaintexts []string    `json:"plaintexts" jsonschema:"Plaintext values"`
	Secrets    []string    `json:"secrets,omitempty" jsonschema:"Salt or secret values"`
	Algorithms []string    `json:"algorithms,omitempty" jsonschema:"Algorithm names; empty selects all supported algorithms"`
	Affixes    sdk.Affixes `json:"affixes,omitempty" jsonschema:"Per-call prefixes and suffixes for plaintext and salt candidates"`
}

type crackInput struct {
	Targets    []string    `json:"targets" jsonschema:"Target hashes, optionally followed by :salt"`
	Plaintexts []string    `json:"plaintexts" jsonschema:"Candidate plaintext values"`
	Secrets    []string    `json:"secrets,omitempty" jsonschema:"Candidate salt values"`
	Algorithms []string    `json:"algorithms,omitempty" jsonschema:"Algorithm names; empty selects all supported algorithms"`
	Affixes    sdk.Affixes `json:"affixes,omitempty" jsonschema:"Per-call prefixes and suffixes for plaintext and salt candidates"`
}

type builtinCrackInput struct {
	Targets    []string    `json:"targets" jsonschema:"Target hashes, optionally followed by :salt"`
	Algorithms []string    `json:"algorithms,omitempty" jsonschema:"Algorithm names; empty selects all supported algorithms"`
	Affixes    sdk.Affixes `json:"affixes,omitempty" jsonschema:"Per-call prefixes and suffixes for plaintext and salt candidates"`
}

type decryptInput struct {
	Targets    []string    `json:"targets" jsonschema:"Target values"`
	Secrets    []string    `json:"secrets,omitempty" jsonschema:"Candidate secrets"`
	Algorithms []string    `json:"algorithms,omitempty" jsonschema:"Algorithm names; empty selects all reversible algorithms"`
	Affixes    sdk.Affixes `json:"affixes,omitempty" jsonschema:"Per-call salt prefix and suffix for candidate secrets"`
}

type emptyInput struct{}
type emptyOutput struct {
	OK bool `json:"ok"`
}

// registerTools maps every public SDK operation to an MCP tool.
func registerTools(server *mcp.Server, client *sdk.Client, limits inputLimits, limiter *toolLimiter) {
	mcp.AddTool(server, &mcp.Tool{Name: "list_algorithms", Description: "List supported algorithms and their metadata."},
		limitedTool(limiter, func(context.Context, *mcp.CallToolRequest, emptyInput) (*mcp.CallToolResult, []sdk.AlgorithmInfo, error) {
			return nil, client.ListAlgorithms(), nil
		}))
	mcp.AddTool(server, &mcp.Tool{Name: "identify", Description: "Identify algorithms that may match each hash."},
		limitedTool(limiter, func(_ context.Context, _ *mcp.CallToolRequest, input identifyInput) (*mcp.CallToolResult, []sdk.Identification, error) {
			if err := limits.validate(input.Hashes); err != nil {
				return nil, nil, err
			}
			return nil, client.Identify(input.Hashes), nil
		}))
	mcp.AddTool(server, &mcp.Tool{Name: "encrypt", Description: "Encrypt in-memory plaintext and secret lists."},
		limitedTool(limiter, func(_ context.Context, _ *mcp.CallToolRequest, input encryptInput) (*mcp.CallToolResult, []sdk.EncryptionResult, error) {
			if err := limits.validate(input.Plaintexts, input.Secrets, input.Algorithms); err != nil {
				return nil, nil, err
			}
			if err := limits.validateValues(input.Affixes.PassPrefix, input.Affixes.PassSuffix, input.Affixes.SaltPrefix, input.Affixes.SaltSuffix); err != nil {
				return nil, nil, err
			}
			result, err := client.Encrypt(input.Plaintexts, input.Secrets, input.Algorithms, input.Affixes)
			return nil, result, err
		}))
	mcp.AddTool(server, &mcp.Tool{Name: "crack", Description: "Crack target hashes in real time using the supplied in-memory candidates."},
		limitedTool(limiter, func(_ context.Context, _ *mcp.CallToolRequest, input crackInput) (*mcp.CallToolResult, []sdk.Result, error) {
			if err := limits.validate(input.Targets, input.Plaintexts, input.Secrets, input.Algorithms); err != nil {
				return nil, nil, err
			}
			if err := limits.validateValues(input.Affixes.PassPrefix, input.Affixes.PassSuffix, input.Affixes.SaltPrefix, input.Affixes.SaltSuffix); err != nil {
				return nil, nil, err
			}
			result, err := client.Crack(input.Targets, input.Plaintexts, input.Secrets, input.Algorithms, input.Affixes)
			return nil, result, err
		}))
	mcp.AddTool(server, &mcp.Tool{Name: "crack_with_builtin_dictionaries", Description: "Crack target hashes in real time using persisted built-in dictionaries."},
		limitedTool(limiter, func(_ context.Context, _ *mcp.CallToolRequest, input builtinCrackInput) (*mcp.CallToolResult, []sdk.Result, error) {
			if err := limits.validate(input.Targets, input.Algorithms); err != nil {
				return nil, nil, err
			}
			if err := limits.validateValues(input.Affixes.PassPrefix, input.Affixes.PassSuffix, input.Affixes.SaltPrefix, input.Affixes.SaltSuffix); err != nil {
				return nil, nil, err
			}
			result, err := client.CrackWithBuiltinDictionaries(input.Targets, input.Algorithms, input.Affixes)
			return nil, result, err
		}))
	mcp.AddTool(server, &mcp.Tool{Name: "decrypt", Description: "Try reversible algorithms against target and secret lists."},
		limitedTool(limiter, func(_ context.Context, _ *mcp.CallToolRequest, input decryptInput) (*mcp.CallToolResult, []sdk.Result, error) {
			if err := limits.validate(input.Targets, input.Secrets, input.Algorithms); err != nil {
				return nil, nil, err
			}
			if err := limits.validateValues(input.Affixes.SaltPrefix, input.Affixes.SaltSuffix); err != nil {
				return nil, nil, err
			}
			result, err := client.Decrypt(input.Targets, input.Secrets, input.Algorithms, input.Affixes)
			return nil, result, err
		}))
	mcp.AddTool(server, &mcp.Tool{Name: "add_plaintexts", Description: "Append plaintext values to the persistent built-in dictionary."},
		limitedTool(limiter, func(_ context.Context, _ *mcp.CallToolRequest, input addPlaintextsInput) (*mcp.CallToolResult, emptyOutput, error) {
			if err := limits.validate(input.Plaintexts); err != nil {
				return nil, emptyOutput{}, err
			}
			if err := client.AddPlaintexts(input.Plaintexts); err != nil {
				return nil, emptyOutput{}, err
			}
			return nil, emptyOutput{OK: true}, nil
		}))
	mcp.AddTool(server, &mcp.Tool{Name: "add_secrets", Description: "Append secret values to the persistent built-in dictionary."},
		limitedTool(limiter, func(_ context.Context, _ *mcp.CallToolRequest, input addSecretsInput) (*mcp.CallToolResult, emptyOutput, error) {
			if err := limits.validate(input.Secrets); err != nil {
				return nil, emptyOutput{}, err
			}
			if err := client.AddSecrets(input.Secrets); err != nil {
				return nil, emptyOutput{}, err
			}
			return nil, emptyOutput{OK: true}, nil
		}))
	mcp.AddTool(server, &mcp.Tool{Name: "init_builtin_dictionaries", Description: "Initialize or reset the persistent built-in dictionaries."},
		limitedTool(limiter, func(_ context.Context, _ *mcp.CallToolRequest, _ emptyInput) (*mcp.CallToolResult, emptyOutput, error) {
			if err := client.InitBuiltinDictionaries(); err != nil {
				return nil, emptyOutput{}, err
			}
			return nil, emptyOutput{OK: true}, nil
		}))
}
