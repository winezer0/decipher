# 命令行问题逐项复核与严重级别排序

当前剩余待办见 [CLI_REMAINING.md](CLI_REMAINING.md)，下文保留修复状态及历史核查记录。

## 修复状态更新

已修复本报告原排序第 1、3、4、5 项：错误返回非零退出码，结果及缓存导出错误向上传递；非法模式在执行前拒绝，保留明确别名和逗号多模式；显式文件无效不再回退；维护完成后直接退出，不创建引擎或重建字典。另修正 output-type 的枚举校验。预计算库生成的文件读写错误也向上传递。

按用户确认的使用场景，原第 2 项不再列为高风险；日志和临时文件的现有默认行为保留，临时文件清理属于低优先级管理问题。

新增 `cmd/decipher/cli_test.go` 覆盖真实子进程退出码、输入校验、维护隔离和多模式兼容；以下为修复前的核查快照，不能作为当前未修复清单。

修复后验证：`go test ./...` 全部通过；重新构建 `bin/decipher.exe`，完成 15 次实际程序调用，覆盖原生中文帮助、正常加密/破解/JSON 导出、非法模式与格式、显式文件缺失、导出失败、清理前校验、维护后退出及未找到明文时正常完成。`git diff --check` 通过。

## 修复前核查快照

复核日期：2026-10-22。依据当前工作区源码重新编译 Windows 程序，并在独立临时目录完成 25 个场景核查。仅生成报告，未修改程序逻辑。

结论：核心错误处理、输入处理和输出问题仍存在；中文帮助、分组、类型占位符和帮助示例已完成。缓存范围、多模式顺序、参数命名及子命令需要与缺陷分开看待。没有发现本轮可确认的 P0 紧急问题。

级别：P1 高，优先修复，会导致无声失败、敏感数据残留或执行非预期操作；P2 中，影响结果正确性、正常操作或脚本集成；P3 低，文档或参数体验问题。排序结合实际影响，部分条目存在共同根因。

## 一、仍存在的缺陷与风险，按严重级别排序

| 排序 | 级别 | 问题及状态 | 本轮证据 | 代码位置 |
| --- | --- | --- | --- | --- |
| 1 | P1 | **导出失败被吞掉，执行失败仍返回 0：确认存在** | dec 指定不存在的输出目录后，结果文件未生成，没有 ERROR 日志，却提示 completed，退出 0。id 默认输出失败、非法格式等错误也退出 0 | `cmd/decipher/decrypt.go:164`、`cmd/decipher/main.go:35` |
| 2 | P1 | **敏感输入明文记录及临时字典残留：确认存在** | 默认 INFO 日志包含测试明文和密钥原值；正常 enc 未传 `-R` 留下两个临时字典。传 `-R` 但因算法不存在提前返回，仍留下一个明文字典 | `cmd/decipher/options.go:196`、`cmd/decipher/resolve.go:64`、`cmd/decipher/encrypt.go:32`、`cmd/decipher/encrypt.go:47` |
| 3 | P1 | **非法模式未被拒绝，可能执行其他操作：确认存在** | `-m typo` 实际执行 dec 并返回 0。模式解析还接受 add/enc/dec/id 前缀，未知值默认 dec；这不是明确枚举校验 | `cmd/decipher/options.go:37`、`internal/cracker/modetype.go:20` |
| 4 | P1 | **显式字典文件缺失仍回退默认字典：确认存在** | `-p file:absent.txt` 警告后使用内置字典，实际破解成功，退出 0。`-i file:absent.txt` 则后续报错但仍退出 0。文件、生成规则解析失败均未通过 error 返回给调用者 | `cmd/decipher/resolve.go:14`、`cmd/decipher/decrypt.go:35` |
| 5 | P1 | **维护操作与业务执行混合：确认存在** | 单独运行 `--cc` 或 `--dc` 后仍进入默认 dec，因无输入报错并返回 0；清理后内置字典又存在。源码确认清理、去重发生在业务校验之前 | `cmd/decipher/options.go:165`、`cmd/decipher/options.go:172`、`cmd/decipher/main.go:31`、`internal/cracker/engine.go:59` |
| 6 | P2 | **enc 的 JSON 输出无效：确认存在** | `-m enc -O json` 生成 `.json` 文件，但 JSON 解析失败；写入的仍是冒号分隔结果行。CSV 选项同样走 WriteLines，并非标准 CSV 序列化 | `cmd/decipher/encrypt.go:52`、`internal/cracker/encrypt.go:64` |
| 7 | P2 | **逗号改变字面量和路径含义：确认存在** | `-p str:a,b` 分别计算 a 和 b，未计算 a,b。已存在的 `words,fixture.txt` 经 `file:` 输入仍被拆开，出现 `File not found: words` | `cmd/decipher/options.go:184` |
| 8 | P2 | **`-o` 的文件/目录语义不统一：确认存在，说明已改善** | id 不传 `-o` 时将默认 `.` 当作文件打开，报错且无结果；enc/dec 则把它当目录。帮助现在如实说明差异，但未改变行为 | `cmd/decipher/options.go:63`、`cmd/decipher/identify.go:29`、`cmd/decipher/encrypt.go:52`、`cmd/decipher/decrypt.go:164` |
| 9 | P2 | **非法输出格式未在解析阶段拒绝：确认存在** | enc 接受 `-O yaml` 并创建 `.yaml` 命名的文本文件；id 接受后才报告格式无效，退出 0。dec 对非 json 值走 CSV 分支 | `cmd/decipher/options.go:64`、`cmd/decipher/identify.go:47`、`cmd/decipher/decrypt.go:165` |
| 10 | P2 | **stdout 混入运行日志，缺少纯结果输出方式：确认存在** | 默认 enc 的 INFO 日志位于 stdout；`-m id -o -` 创建名为 `-` 的普通文件，不表示输出到 stdout。未定义 `--quiet` | `cmd/decipher/options.go:142`、`cmd/decipher/encrypt.go:42`、`cmd/decipher/identify.go:21` |
| 11 | P2 | **固定输出文件被隐式覆盖，缺少用户可控策略：行为存在** | 相同目录先 enc first 再 enc second，输出仅保留 second。是否改成拒绝覆盖或显式选项属于产品选择，但当前确有覆盖已有结果的风险 | `cmd/decipher/encrypt.go:53`、`cmd/decipher/decrypt.go:170`、`internal/export/export.go:65` |
| 12 | P3 | **README 加密示例仍错误使用 `-i`：确认存在** | 运行 README 对应调用后提示 no plain dicts be selected；enc 实际读取 `-p`。命令行帮助示例已正确使用 `-p` | `README.md:297`、`README.md:305`、`cmd/decipher/encrypt.go:15` |
| 13 | P3 | **负数 workers 未被拒绝：确认存在** | `--workers=-1` 正常生成结果。源码将所有 `<= 0` 的值都视为 CPU 数量，不只 0 | `internal/cracker/engine.go:45` |

其中第 2 项证实的是本机日志和磁盘中的敏感数据暴露面，没有据此推断发生远程泄露。成功结果本身也会保存明文，这是工具现有功能，需要与额外的输入日志、临时副本分开管理。

第 4 项中，不加前缀时“同名文件不存在就当作字符串”已写入帮助，属于现有自动识别设计；真正应优先修正的是显式 `file:` 无效后仍回退、继续执行。若需要消除无前缀路径拼写错误的歧义，再引入严格输入方式。

第 5 项仅对临时目录内由测试程序生成的数据执行清理，未清理仓库或用户已有缓存。源码与运行均确认会重建字典；本轮没有用用户指定的任意目录验证清理边界。

## 二、已改善、现有设计及待选优化

| 原条目 | 核查状态 | 判断 |
| --- | --- | --- |
| 中文说明、参数分组、帮助示例 | **已完成** | 使用 go-flags 原生帮助，无自定义排版；中文有效 UTF-8，包含 STRINGS、STRING、INT、PATH 占位符和示例。库自身的 Usage、Help Options、default 等固定文字仍为英文 |
| 帮助说明默认字典、输入前缀及副作用 | **大部分完成** | 已说明 file:/str:/gen:、逗号拆分、内置字典、enc 必须用 `-p`、多模式顺序及维护行为；仍可补充 Windows 路径、转义示例和完整模式参数矩阵 |
| `--nhc` 不影响成功结果缓存 | **行为确认，属于已说明的设计** | 开启 `--nhc` 的第一次破解仍写 success.cache，第二次换错误候选仍复用成功结果。它禁用运行计算缓存；当前帮助和 README 已明确范围，不应继续直接归为参数失效 |
| 多模式固定顺序 | **行为确认，帮助已说明** | 即使传 `-m dec,enc`，仍先 enc 后 dec；不是按输入顺序执行，也不是将上一模式结果传给下一模式。没有证据表明当前文档承诺了后两种行为 |
| `-` 表示内置字典，未支持 stdin | **行为确认，属于接口选择** | 向进程 stdin 提供独特测试词，`-p -` 仍选择内置字典，输出未使用 stdin 的词。改为 stdin 会破坏既有调用，需要明确迁移方案 |
| 显式空字符串作为空盐 | **已支持，不应列为缺失功能** | `-s str:` 配合 `md5($pass.$salt)` 已生成预期空盐结果。仍未区分“缺失盐文件”和“未提供盐”，这是输入错误处理问题 |
| 易读参数别名 | **尚未添加，设计建议** | 当前仍保留原名称；未实现 `--input`、`--wordlist`、`--secret-file`、`--algorithm`、`--algorithm-match`、`--salt-prefix/--salt-suffix`、`--plain-prefix/--plain-suffix`、`--no-predb`、`--no-dynamic`、`--no-runtime-cache`、`--log-level/--log-file/--log-format`、`--list-algorithms` 等建议名称 |
| 默认清理、`--keep-temp` | **尚未实现** | 当前默认保留；`-R/--rr` 仅在走到清理代码时生效。默认策略可讨论，但失败路径不清理应优先修复 |
| `--append` / `--overwrite` | **尚未实现，策略待定** | 各导出函数自行决定覆盖或追加；已复现 enc 覆盖已有结果 |
| 子命令结构 | **尚未实现，架构建议** | 仍使用 `-m`，没有 identify/encrypt/crack/cache 等子命令；无需为修复 P1/P2 问题而先做整体迁移 |
| add 同时更新内置字典与生成预计算库 | **源码确认，设计行为** | `addedAction` 先追加内置字典再调用 CreatePredb；是否拆为两个命令属于后续设计决策 |

## 三、已定位的根因

1. **枚举约束标签写错。** 项目使用 `choices:"..."`，但 go-flags v1.6.1 读取的是重复的 `choice` 标签，例如 `choice:"add" choice:"enc"`。所以 mode 和 output-type 的声明没有生效。修改标签时还需兼顾现有逗号多模式用法，不能直接改完便假定兼容。
2. **缺少统一错误返回入口。** main 记录 action 错误后不设置失败退出码；部分导出、缓存、去重调用甚至忽略错误。只改日志文本不能解决。
3. **校验、维护、输入转换和业务执行交织。** 无效输入可能已产生文件或触发清理；输入解析只返回路径，不返回明确错误，调用方无法可靠区分未提供与处理失败。
4. **临时资源没有在创建后立即登记清理。** action 的提前返回会绕过底部清理代码。

## 四、建议修复顺序

1. 先修复 P1：统一错误传播和退出码；输入与枚举预校验；减少敏感输入日志并保证异常路径清理；维护操作独立结束。
2. 再修复 P2：正确序列化、完整保留字符串与路径、统一输出语义、纯结果输出及明确覆盖策略。
3. 最后修正文档和负数校验。参数别名、stdin 和子命令另行决定，不与缺陷修复捆绑。

## 五、验证范围

重新编译：`go build -trimpath -ldflags "-s -w" -o bin/decipher.exe ./cmd/decipher`，成功。

25 个场景：id 默认输出、enc JSON、dec 导出失败、缺失显式输入文件、缺失显式字典、缺失无前缀文件、cc、dc、含逗号字面量、nhc 成功缓存、逆序多模式、非法模式、enc 非法格式、id 非法格式、默认临时文件及日志、失败路径带 R、stdout 日志、输出 `-`、负数 workers、README 示例、隐式覆盖、原生中文帮助、含逗号的现存文件、显式空盐、stdin 与内置字典。

测试产物：`C:\Users\windows\AppData\Local\Temp\decipher-issues-voel2r09` 及另一个 `decipher-edges-` 前缀临时目录。只使用人工测试字符串，不含实际凭据。

本轮属于行为复核；“场景已核查”不代表这些缺陷已修复，也不代表所有算法、平台和权限条件均已覆盖。
