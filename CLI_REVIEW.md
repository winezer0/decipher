# 命令行参数优化分析

当前剩余待办见 [CLI_REMAINING.md](CLI_REMAINING.md)。本文保留为初始分析，部分问题现已修复。

建议先统一参数的实际行为和校验，再改善命名；子命令作为后续可选改造。此次仅做静态分析，未修改程序、未运行功能测试。

## 先修复行为问题

| 优先级 | 当前问题 | 建议 |
| --- | --- | --- |
| 高 | `-o` 声明为目录，enc/dec 拼接文件名，id 却直接作为文件路径；默认 `.` 在 id 中会被当作输出文件 | 统一 `--output` 为文件路径，另设 `--output-dir`；二者互斥。多模式时要求输出目录 |
| 高 | enc 的 `--output-type json` 只改变扩展名，仍调用 WriteLines 写入结果 | 各模式使用真正的 CSV/JSON 序列化；明确 JSON 数组或 JSONL |
| 高 | main 中 action 返回错误后仅记录日志，进程仍正常结束；dec 的结果导出错误也未向上传递 | 统一返回错误和非零退出码；参数错误与运行错误分开，部分破解成功不等同于执行失败 |
| 高 | 输入文件不存在时可能被当作字符串；显式 `file:` 不存在只警告，后续可能回退默认字典 | 显式文件错误立即失败；区分“未提供字典”和“提供了无效字典” |
| 高 | 清理、去重在参数初始化期间执行，随后仍创建引擎并进入默认 dec；引擎可能重新生成刚清理的内置字典 | 维护操作单独执行并退出；完整校验先于文件写入或删除 |
| 中 | 所有输入均经过逗号拆分，包括 `str:` 和文件路径 | 字面量和路径保持原样；多值优先用重复参数，逗号列表仅保留给算法等明确列表 |
| 中 | `--nhc` 传给 RunHashCrack，但成功结果缓存仍独立读写 | 将运行计算缓存与成功结果缓存分开命名和控制；提供清晰的总禁用选项 |
| 中 | 多模式按 add → id → enc → dec 固定执行，与命令行输入顺序无关 | 帮助中明确顺序；若支持流水线，显式定义数据是否传递，目前各 action 并非结果串联 |

相关实现：`cmd/decipher/options.go`、`main.go`、`resolve.go`、`encrypt.go`、`decrypt.go`、`identify.go`。

## 参数命名与输入设计

保留现有短参数，并为难理解的长参数添加易读别名；旧名称至少保留一个兼容周期。

| 当前名称 | 建议名称 | 说明 |
| --- | --- | --- |
| `--hashes` | `--input` | id/dec 输入目标；enc 仍明确使用 `--plain` |
| `--plains` | `--plain`、`--wordlist` | 区分单个明文与候选字典文件 |
| `--secrets` | `--secret`、`--secret-file` | 兼容盐和加密密钥，避免全部改称 salt |
| `--algos` | `--algorithm` | 重复传入支持多个算法 |
| `--precise` | `--algorithm-match exact\|contains` | 当前默认关键词匹配；建议先保留默认行为，新增显式匹配方式 |
| `--sp` / `--ss` | `--salt-prefix` / `--salt-suffix` | 长参数无需压缩成缩写 |
| `--pp` / `--ps` | `--plain-prefix` / `--plain-suffix` | 统一明文术语 |
| `--npc` | `--no-predb` | 说明禁用预计算数据库后，相关算法仍会现场计算 |
| `--ndc` | `--no-dynamic` | 明确只跳过动态算法阶段，并非禁止全部现场计算 |
| `--nhc` | `--no-runtime-cache` | 明确实际影响范围 |
| `--ll` / `--lf` / `--lcf` | `--log-level` / `--log-file` / `--log-format` | 易读、便于补全 |
| `--list` | `--list-algorithms` | 明确列出的对象 |

输入建议：

- 将 `-` 用于 stdin；内置字典改用 `builtin:` 或 `--builtin-wordlist`。该变更影响旧命令，应分阶段迁移。
- 保留 `file:`、`str:`、`gen:` 的兼容入口；帮助中解释优先级、转义及 Windows 路径示例。
- 显式空字符串应能代表空盐，与“没有提供盐”和“盐文件无效”分别处理。
- `--workers 0` 明确表示 CPU 数量，拒绝负数；当前实现把所有非正数都当作自动值。
- 模式按明确枚举校验，拒绝拼写错误；当前 ResolveMode 对未知值回退 dec，不宜作为容错策略。参数解析器的 choices 标签是否实际拦截全部非法输入，需另做运行验证。

## 帮助、默认值与脚本使用

- 帮助按“操作、输入、算法、性能、输出、缓存、日志”分组，显示每个模式的必填参数、默认字典及副作用。
- 修正 README 中 `-m enc -i password` 的示例：当前 encryptAction 读取 `-p`，不读取 `-i`。
- stdout 只输出结果，日志写 stderr；提供 `--quiet`。`--output -` 可明确输出到 stdout。
- 明确覆盖和追加规则，提供 `--append` / `--overwrite`，避免仅靠各导出函数决定。
- 临时文件默认自动清理，提供 `--keep-temp` 用于排查；错误路径也执行清理。当前必须传 `--rr` 才清理。
- 不在 info 日志中直接打印 Used Plains、Used Secrets 的字面量内容；提供文件或 stdin 输入，减少命令行传递敏感值的需求。

## 可选：按任务拆分子命令

长期可以使用以下结构；这是设计建议，当前程序尚不支持：

```text
decipher identify --input-file hashes.txt --output identified.json --format json
decipher encrypt --plain example --algorithm md5 --output encrypted.csv
decipher crack --input-file hashes.txt --wordlist words.txt --algorithm md5
decipher predb build --wordlist words.txt --algorithm md5
decipher dict add --wordlist words.txt
decipher cache clean
decipher cache dedup
decipher algorithms list
```

将当前 add 的“更新内置字典”和“生成预计算库”拆开，操作目的更明确。旧 `-m add/enc/dec/id` 可通过兼容入口映射；如需保留一次执行多个模式，应单独定义组合规则。

## 建议实施顺序

1. 统一输出语义、序列化与退出码，完善输入校验，隔离维护操作。
2. 添加易读别名、参数分组及准确示例，保留旧调用方式。
3. 确认兼容要求后，再迁移 stdin、默认清理行为和子命令结构。

验证重点：各模式默认输出路径、JSON 可解析性、失败退出码、含逗号的字面量和路径、缺失文件不回退、缓存禁用范围、维护操作执行后立即退出。
