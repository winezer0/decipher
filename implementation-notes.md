# Implementation Notes

## Go SDK boundary

- Added the `sdk` package as the stable Go SDK entry point. The SDK depends on internal algorithm and cracking packages; external callers only use exported request, result, configuration, and client types.
- SDK calls accept in-memory string lists for plaintexts, targets, and secrets, and return structured result slices with JSON field tags. They do not invoke CLI parsing or output exporters.
- SDK runtime files default to the operating system user cache directory. Callers can override the built-in dictionary data directory and run-cache path.
- Changed the module path to `github.com/winezer0/decipher` so external Go modules can import the SDK.
- The API covers algorithm listing, hash identification, encryption, real-time candidate cracking, streaming cracks against persisted built-in dictionaries, and reversible decryption.

## MCP HTTP entry point

- Added the standalone `mcp` executable package, which exposes every public `sdk.Client` operation as an MCP tool over Streamable HTTP at `/mcp`.
- The server binds to `127.0.0.1:8080` by default; listen address, SDK data/cache directories, and worker count are configurable through flags. Loopback is the default because dictionary mutation tools write persistent data.
- Tool parameters use in-memory string arrays. Both cracking tools remain real-time; the built-in dictionary variant streams persisted dictionaries through the SDK.
- The MCP package depends on the public SDK and the official Go MCP SDK; it does not import internal decipher packages.
- Standardized SDK algorithm and identification JSON fields to lowercase snake case for MCP structured output.
- Remote bind addresses require `DECIPHER_MCP_TOKEN` and Bearer authorization. The HTTP server now has graceful signal shutdown, header/read/idle timeouts, request body and input-list limits, and a shared non-blocking concurrent tool-call limit. Defaults balance local usability with bounded request memory and CPU use; MCP write timeout remains disabled for long-running real-time cracking calls.
- Affixes are passed as per-call SDK/MCP operation options, not startup configuration. SDK operations use an operation-local engine copy so concurrent requests cannot leak or overwrite each other's affixes. Encryption and cracking apply pass affixes to plaintext candidates and salt affixes to salts; decryption applies only salt affixes to candidate keys.
- Reversible decryption tries each selected reversible algorithm through `Recover` instead of using hash identification as a prefilter, because encrypted payloads may not match the algorithm's hash-identification heuristic.
- CLI precomputed databases and success caches use a SHA-256 scope derived from the four affix values. Matching settings share the same cache scope; different settings cannot mix precomputed or previously recovered results. Affix-scoped precomputed files live in `affix-<fingerprint>` subdirectories, so cache deduplication walks nested directories.
