# 安全修复清单 P0/P1

> 基线：`bfdad71`（上一轮安全审计修复 v1.1 之后）
> 范围：基线之后工作区全部未提交修改（3 个修改文件 + 2 个新增测试文件）
> 验证：`go build ./...`、`go vet ./...`、`go test ./...` 均通过

本轮针对「安全审计 v1.1 之后代码复查」发现的 P0/P1 风险进行修复，覆盖命令递归 DoS、VFS 全局容量失控、共享引用数据竞争与输出累积放大四类问题。

---

## 一、P0 修复（必须修复）

| 编号 | 问题 | 修复内容 | 文件 |
| --- | --- | --- | --- |
| P0-1 | `sudoCmd` 递归调用 `Execute()` 无深度上限：`sudo sudo sudo ... ls`（N 层）逐层重新进入完整解析，每层分配 `execCtx`、发布事件、拷贝缓冲区并叠加 `simDelay`（约 25ms/层），可造成进程级 DoS（时间放大 + 分配放大 + 栈压力） | ① `Execute` 重构为带深度的内部入口 `executeDepth(..., depth)`，`sudo` 递归复用 `maxCmdSubstDepth = 32` 上限；② 新增 `stripLeadingSudo`，`sudo sudo sudo ls` 一次性折叠为 `ls`，避免逐层重入；③ 深度超限直接拒绝并输出 `sudo: too many levels of nested sudo`；④ 保留 `sudo -l`/`sudo -u root` 等选项语义不破坏 | `internal/shell/executor.go` |
| P0-2 | VFS 无全局节点数/字节数预算：`touch` 循环可塞百万节点、SFTP 并发上传可撑爆 heap、跨会话共享同一 VFS 使垃圾永久累积 | 新增全局预算 `maxTotalNodes = 200000`、`maxTotalBytes = 2 GiB`；`FileSystem` 增加 `totalNodes`/`totalBytes` 计数；所有写路径接入预算：`WriteFile`/`AppendFile`（新建节点 + 字节增量校验）、`Mkdir`、`Copy`（目标存在校验）、`Remove`/`RemoveAll`（按 `subtreeStats` 递归回退计数）；`New` 后 `recountUsage()` 统计 bootstrap 初始值 | `internal/vfs/vfs.go` |

## 二、P1 修复（高优先级）

| 编号 | 问题 | 修复内容 | 文件 |
| --- | --- | --- | --- |
| P1-1 | `ReadFile` 在 `RLock` 下返回共享内容 slice，解锁后与写路径 `append` 共享底层数组，存在数据竞争；`Walk` 回调在 `RLock` 内执行，若回调内调用写方法会 RLock→Lock 死锁 | ① `ReadFile` 返回内容副本（`append([]byte(nil), n.content...)`），杜绝共享底层数组；② `Walk` 文档明确「回调内严禁调用写方法」，仅允许只读 `FileInfo` | `internal/vfs/vfs.go` |
| P1-2 | 命令链输出中间累积放大：`limitOutput` 仅在外层 `Execute` 截断，`;`/`&&`/`\|\|`/`\|` 串联的中间 `out` 可被撑到 N×8 MiB 才截断，造成内存放大 | 新增 `capOut` 中间软上限（超 `maxOutputSize` 截断前缀，不追加提示），应用在 `runSequence`（`;` 链）、`runAndOr`（`&&`/`\|\|` 链）、`runAST` 多语句循环、`runPipeChain` 管道合并；最外层 `limitOutput` 统一截断加提示 | `internal/shell/executor.go`、`internal/shell/parse.go` |
| P1-3 | SFTP 上传独立绕过单文件大小限制（已由 P0-2 覆盖）：SFTP `flush` 走 `fs.WriteFile` → `lockedWrite`，自动受全局字节/节点预算约束；SSH 层已有 `MaxConnections`/`chanSem` 并发上限 | 无需额外改动，由 P0-2 全局预算兜底 | `internal/ssh/sftp.go`（未改动） |
| P1-4 | 命令替换深度仅限 `$()` 与 `()`，其它 `Execute()` 重入点可能绕过（已由 P0-1 覆盖）：`sudoCmd` 是唯一 `Execute` 重入点，现复用 `maxCmdSubstDepth`，与命令替换/子 shell 深度检查一致 | 无需额外改动，由 P0-1 统一守护 | `internal/shell/executor.go` |

## 三、回归测试

| 测试文件 | 覆盖场景 |
| --- | --- |
| `internal/vfs/budget_test.go` | 节点预算耗尽拒绝、字节预算耗尽拒绝、删除/`RemoveAll` 后计数回退、`Copy` 预算计数 |
| `internal/shell/sudo_test.go` | `stripLeadingSudo` 边界（独立单词、`sudo -u`、`sudosomething`）、1000 层 `sudo` 链不爆栈、命令替换嵌套不 panic、普通 `sudo` 行为不变 |

---

## 遗留问题（未在本轮处理）

- `maxTotalNodes`/`maxTotalBytes` 目前为常量，建议后续挪入 `config.VFSConfig` 支持按部署调参。
- P2 项（默认口令审计、sessionPid 区分度、`wget`/`curl` 出站限制、审计日志完整性）计划在下一迭代处理。
