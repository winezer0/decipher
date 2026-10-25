# Decipher MCP Server

独立 HTTP MCP 入口，封装 `sdk` 包的全部公开操作，使用 Streamable HTTP，端点为 `/mcp`。

```powershell
go run ./mcp
```

默认监听 `127.0.0.1:8080`。可通过 `-addr`、`-data-dir`、`-cache-dir` 和 `-workers` 配置监听地址、字典目录、运行缓存目录和工作线程数。

非本机监听必须设置环境变量 `DECIPHER_MCP_TOKEN`，客户端使用 `Authorization: Bearer <token>`。远程部署应通过 HTTPS 反向代理保护传输中的令牌。可通过 `-max-request-body-bytes`、`-max-list-items`、`-max-value-bytes` 和 `-max-concurrent-calls` 调整请求体、每次工具调用的字符串列表总项数、单个字符串和并发工具调用上限。默认分别为 4 MiB、10000 项、64 KiB 和 4 个并发调用。

## 客户端连接

在 MCP 客户端中将服务器地址设为 `http://127.0.0.1:8080/mcp`。本机默认监听无需令牌；远程客户端应使用 HTTPS 地址，并为请求添加 `Authorization: Bearer <token>`，其中令牌与服务端的 `DECIPHER_MCP_TOKEN` 一致。客户端配置文件格式因客户端而异，传输方式统一选择 Streamable HTTP。

远程部署时，可在 PowerShell 中这样启动服务：

```powershell
$env:DECIPHER_MCP_TOKEN = "replace-with-a-random-token"
go run ./mcp -addr 0.0.0.0:8080
```

客户端请求需带上 `Authorization: Bearer replace-with-a-random-token`，并通过 HTTPS 反向代理访问服务。

## Go 客户端调用示例

下面使用同一 Go MCP SDK 连接服务并调用 `encrypt` 工具。服务端默认监听本机地址：

```go
package main

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func main() {
	ctx := context.Background()
	client := mcp.NewClient(&mcp.Implementation{Name: "decipher-example", Version: "1.0.0"}, nil)
	session, err := client.Connect(ctx, &mcp.StreamableClientTransport{
		Endpoint:             "http://127.0.0.1:8080/mcp",
		DisableStandaloneSSE: true,
	}, nil)
	if err != nil {
		panic(err)
	}
	defer session.Close()

	result, err := session.CallTool(ctx, &mcp.CallToolParams{
		Name: "encrypt",
		Arguments: map[string]any{
			"plaintexts": []string{"hello"},
			"algorithms": []string{"base64($pass)"},
			"affixes": map[string]string{
				"pass_prefix": "pre-",
				"pass_suffix": "-post",
			},
		},
	})
	if err != nil {
		panic(err)
	}
	if result.IsError {
		panic(result.Content)
	}

	output, err := json.MarshalIndent(result.StructuredContent, "", "  ")
	if err != nil {
		panic(err)
	}
	fmt.Println(string(output))
}
```

预期结构化结果如下；`hash` 是对添加前后缀后的 `pre-hello-post` 进行 Base64 编码的结果：

```json
[
  {
    "algorithm": "base64($pass)",
    "hash": "cHJlLWhlbGxvLXBvc3Q=",
    "salt": "",
    "plaintext": "hello"
  }
]
```

调用其他工具时，将 `Name` 改为工具名，并按下表传入对应参数。客户端也可以通过 `session.ListTools(ctx, &mcp.ListToolsParams{})` 获取服务端提供的工具和参数 schema。

服务收到中断或终止信号时会优雅关闭；HTTP 请求头、请求读取和空闲连接均配置超时。MCP 响应不设置写超时，以允许较长的实时破解任务完成。

| 工具 | 参数 |
| --- | --- |
| `list_algorithms` | 无 |
| `identify` | `hashes: string[]` |
| `encrypt` | `plaintexts: string[]`；可选 `secrets`、`algorithms`、`affixes` |
| `crack` | `targets: string[]`、`plaintexts: string[]`；可选 `secrets`、`algorithms`、`affixes` |
| `crack_with_builtin_dictionaries` | `targets: string[]`；可选 `algorithms`、`affixes` |
| `decrypt` | `targets: string[]`；可选 `secrets`、`algorithms`、`affixes` |
| `add_plaintexts` | `plaintexts: string[]` |
| `add_secrets` | `secrets: string[]` |
| `init_builtin_dictionaries` | 无 |

列表参数均为内存字符串数组；破解工具实时运行。字典追加和初始化会持久化到 SDK 数据目录。

加密、实时破解、内置字典破解和解密工具支持每次调用独立传入可选 `affixes` 对象，例如 `{"pass_prefix":"pre-","pass_suffix":"-post","salt_prefix":"s-","salt_suffix":"-end"}`。明文候选使用 pass 前后缀，salt 候选使用 salt 前后缀；解密只对候选密钥应用 salt 前后缀。省略字段或使用空字符串表示不添加前后缀。
