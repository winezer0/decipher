# 测试指南

## 常用检查

从仓库根目录运行：

```bash
go test ./...
go test -race ./...
go vet ./...
go build -o bin/decipher.exe ./cmd/decipher
```

不使用 Go 测试缓存的完整运行：

```bash
go test -count=1 ./...
```

Windows 专用测试包含在 `go test ./...` 中；它们会通过独立子进程检查峰值工作集和大输入行为。

## 覆盖范围

- `cmd/decipher`：命令解析、enc/dec/id/dict 操作、输出格式、临时文件清理、成功缓存和 CLI 集成。
- `internal/algo`：算法结果、盐与密码组合顺序、摘要格式、边界字节和准备校验路径。
- `internal/cracker`：字典读取、目标解析、固定与动态破解、多字典、预计算策略、共享盐、结果顺序、重复目标、取消和进度字节计数。
- `internal/export`：加密/导入导出的流式结果、错误传播与取消。
- `*_benchmark_test.go`：性能基准，使用 `go test -bench` 单独运行；常规全量测试不会执行基准。
- Windows 内存测试：检查字典、Worker 和预计算策略的峰值内存及长输入行为。

## 运行单项基准

例如：

```bash
go test ./internal/cracker -run '^$' -bench 'BenchmarkPreparedPipeline' -benchmem
go test ./internal/cracker -run '^$' -bench 'BenchmarkMultiDictionaryPreparation' -benchmem
go test ./internal/cracker -run '^$' -bench 'BenchmarkProgressDispatch|BenchmarkLongDictionaryProgress' -benchmem
```

性能对比应在同一台机器、相同 Go 版本和数据规模下交替测量前后版本。报告耗时及分配量；短命令的端到端结果也包含进程启动、文件和控制台开销，不能直接等同于哈希循环速度。
