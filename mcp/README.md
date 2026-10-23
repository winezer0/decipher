# Decipher MCP Server

独立 HTTP MCP 入口，封装 `sdk` 包的全部公开操作，使用 Streamable HTTP，端点为 `/mcp`。

```powershell
go run ./mcp
```

默认监听 `127.0.0.1:8080`。可通过 `-addr`、`-data-dir`、`-cache-dir` 和 `-workers` 配置监听地址、字典目录、运行缓存目录和工作线程数。

非本机监听必须设置环境变量 `DECIPHER_MCP_TOKEN`，客户端使用 `Authorization: Bearer <token>`。远程部署应通过 HTTPS 反向代理保护传输中的令牌。可通过 `-max-request-body-bytes`、`-max-list-items`、`-max-value-bytes` 和 `-max-concurrent-calls` 调整请求体、每次工具调用的字符串列表总项数、单个字符串和并发工具调用上限。默认分别为 4 MiB、10000 项、64 KiB 和 4 个并发调用。

服务收到中断或终止信号时会优雅关闭；HTTP 请求头、请求读取和空闲连接均配置超时。MCP 响应不设置写超时，以允许较长的实时破解任务完成。

提供的 MCP tools：`list_algorithms`、`identify`、`encrypt`、`crack`、`crack_with_builtin_dictionaries`、`decrypt`、`add_plaintexts`、`add_secrets`、`init_builtin_dictionaries`。

列表参数均为内存字符串数组；破解工具实时运行。字典追加和初始化会持久化到 SDK 数据目录。

加密、实时破解、内置字典破解和解密工具支持每次调用独立传入可选 `affixes` 对象，例如 `{"pass_prefix":"pre-","pass_suffix":"-post","salt_prefix":"s-","salt_suffix":"-end"}`。明文候选使用 pass 前后缀，salt 候选使用 salt 前后缀；解密只对候选密钥应用 salt 前后缀。省略字段或使用空字符串表示不添加前后缀。
