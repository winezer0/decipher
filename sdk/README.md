# Go SDK API

SDK 位于 `sdk` 目录，导入路径为 `github.com/winezer0/decipher/sdk`。它在调用方进程内运行，操作参数使用内存字符串列表，方法返回带 JSON 标签的结构体切片。内置字典破解会流式读取已持久化的内置字典。

## 安装与创建客户端

```sh
go get github.com/winezer0/decipher/sdk
```

```go
package main

import sdk "github.com/winezer0/decipher/sdk"

func main() {
	client, err := sdk.NewClient(sdk.Config{})
	if err != nil {
		panic(err)
	}
	_ = client
}
```

`Config{}` 的默认目录位于当前用户缓存目录下的 `decipher/data` 和 `decipher/cache`。SDK 会创建这些目录并初始化内置字典。可通过 `DataDir` 和 `RunCacheDir` 指定其他路径。`Workers` 为 0 时按 CPU 数量选择；负数会返回错误。

`Encrypt`、`Crack`、`CrackWithBuiltinDictionaries` 和 `Decrypt` 的最后一个参数是可选的 `Affixes`。前后缀按调用生效，不会修改共享客户端配置，也适用于并发调用。加密和破解会给明文候选应用 `PassPrefix`/`PassSuffix`，并给 salt 候选应用 `SaltPrefix`/`SaltSuffix`；解密仅给候选密钥应用 salt 前后缀。

## 算法查询与识别

```go
algorithms := client.ListAlgorithms()
identified := client.Identify([]string{"5d41402abc4b2a76b9719d911017c592"})
```

- `ListAlgorithms()` 返回 `[]AlgorithmInfo`，包含名称、类型、是否需要 salt、算法元数据。
- `Identify(hashes)` 返回 `[]Identification`。输入可为哈希或 `hash:salt`；空行和 `#` 注释行会跳过。
- 两个方法都不返回错误。

算法名称需使用 `ListAlgorithms` 返回的完整名称。算法列表为空时，选择全部适用算法。

## 加密

```go
encrypted, err := client.Encrypt(
	[]string{"hello", "world"},
	[]string{"salt-a", "salt-b"},
	[]string{"base64($pass)"},
	sdk.Affixes{PassPrefix: "pre-", PassSuffix: "-post"},
)
```

参数依次为内存明文列表、salt 列表和算法列表。`Secrets` 为空时使用空 salt。返回 `[]EncryptionResult`，字段包括算法、结果值、salt 和明文。

## 哈希恢复

```go
cracked, err := client.Crack(
	[]string{"5d41402abc4b2a76b9719d911017c592"},
	[]string{"wrong", "hello"},
	nil,
	[]string{"md5($pass)"},
	sdk.Affixes{},
)
```

参数依次为目标哈希列表、候选明文列表、候选 salt 列表和算法列表。目标也可用 `hash:salt` 格式指定 salt。SDK 始终实时计算，不查询预计算数据库。返回 `[]Result`，包含找到的明文、算法、类型和 salt。

需要使用之前追加的内置字典时，可调用流式破解函数：

```go
if err := client.AddPlaintexts([]string{"hello", "world"}); err != nil {
	panic(err)
}
cracked, err := client.CrackWithBuiltinDictionaries(
	[]string{"5d41402abc4b2a76b9719d911017c592"},
	[]string{"md5($pass)"},
	sdk.Affixes{},
)
```

该方法从 `DataDir` 中逐行读取内置明文和 salt 字典，不会把整个文件载入内存；破解仍为实时计算。

## 可逆算法解密

```go
decrypted, err := client.Decrypt(
	[]string{"aGVsbG8="},
	[]string{"key-a", "key-b"},
	[]string{"base64($pass)"},
	sdk.Affixes{},
)
```

参数依次为密文列表、候选密钥列表、算法列表和调用级 `Affixes`。解密仅将 salt 前后缀应用于候选密钥，不会修改返回的原始候选值。返回值为 `[]Result`。

## 内置字典

```go
if err := client.AddPlaintexts([]string{"hello", "world"}); err != nil {
	panic(err)
}
if err := client.AddSecrets([]string{"salt-a", "salt-b"}); err != nil {
	panic(err)
}
if err := client.InitBuiltinDictionaries(); err != nil {
	panic(err)
}
```

`AddPlaintexts` 和 `AddSecrets` 将值追加到客户端配置的数据目录中的内置字典。`InitBuiltinDictionaries` 确保内置明文和 salt 字典存在，不会生成预计算数据库。传入值必须是单行非空字符串，不能传文件路径。

## 结果序列化

SDK 返回结构体切片；字段带有 JSON 名称，可由调用方按需序列化：

```go
data, err := json.Marshal(encrypted)
```

使用 `json.Marshal` 时需导入标准库 `encoding/json`。

## 错误处理

`NewClient`、字典操作、`Encrypt`、`Crack` 和 `Decrypt` 在目录、输入值或算法参数无效时返回错误。识别和计算结果通过结构体切片返回，调用方无需解析 CLI 输出。
