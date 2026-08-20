# SSH 高交互蜜罐架构方案（honeypot-go）

## 1. 定位与威胁模型

**定位**：高交互蜜罐 ≠ 真机执行。它的价值在于**以极低的真实风险换取极高的攻击行为可见度**——诱捕、记录、分析攻击者的完整攻击链（扫描 → 爆破 → 登录 → 提权侦察 → 投放恶意载荷 → 横向移动），而不是让攻击者真正攻陷系统。

**威胁模型（蜜罐要捕捉的行为）**：

| 阶段 | 典型行为 | 需要捕获的信息 |
|---|---|---|
| 侦察 | 端口扫描、SSH 指纹探测 | 源 IP、探测频率、客户端版本 |
| 爆破 | 弱口令字典、用户名枚举 | 用户名/密码字典、时间模式 |
| 登录 | 成功登录后的第一条命令 | 命令、TERM、PTY 参数 |
| 提权/侦察 | `uname`、`id`、`cat /etc/passwd`、`find /` | 命令序列、时序 |
| 载荷投递 | `wget/curl`、`base64 -d`、`echo >`、SCP/SFTP | 下载 URL、文件内容 hash |
| 持久化 | crontab、rc.local、ssh authorized_keys | 写文件内容 |
| 横向 | 反弹 shell、内网扫描、代理 | 目标 IP/端口、隧道特征 |

**核心原则**：

1. **仿真而非执行**——所有命令、文件、网络行为都在用户态模拟，蜜罐自身永不"中毒"。
2. **只进不出**——默认禁止出站，杜绝蜜罐被当作跳板。
3. **一切皆事件**——把每一次按键、每条命令、每个字节输出都变成可回放、可关联、可告警的结构化事件。

## 2. 总体架构（分层）

```
┌─────────────────────────────────────────────────────────────────┐
│                       管理平面 Management Plane                  │
│   YAML 配置中心 │ REST/CLI 管理 API │ Prometheus 遥测 │ SIEM 对接 │
├─────────────────────────────────────────────────────────────────┤
│                       接入层 Network Frontend                   │
│   多端口监听 │ TCP 代理/转发 │ IP 指纹伪装 │ 速率限制 │ 黑白名单   │
├─────────────────────────────────────────────────────────────────┤
│                    协议引擎 SSH Protocol Engine                 │
│   KEX/版本协商 │ channel 管理 │ auth 方法分发 │ PTY 参数传递      │
├─────────────────────────────────────────────────────────────────┤
│                    认证欺骗层 Auth Emulation                    │
│   弱口令库 │ 字典攻击响应 │ keyboard-interactive │ 公钥伪造        │
├─────────────────────────────────────────────────────────────────┤
│                   交互仿真层 Interaction Emulation              │
│  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌───────────────┐       │
│  │ Shell    │ │ VFS 虚拟 │ │ VNet 虚拟│ │ Terminal      │       │
│  │ 解释器   │ │ 文件系统 │ │ 网络命令 │ │ 仿真(PTY)     │       │
│  └──────────┘ └──────────┘ └──────────┘ └───────────────┘       │
├─────────────────────────────────────────────────────────────────┤
│                   行为分析层 Behavior Analysis                  │
│   事件总线(内存) │ 规则引擎 │ 攻击链关联 │ 风险评分 │ 告警         │
├─────────────────────────────────────────────────────────────────┤
│                    记录与存储层 Recording & Storage             │
│   ttyrec 会话回放 │ 事件存储(SQLite) │ 原始日志(JSONL)           │
└─────────────────────────────────────────────────────────────────┘
```

**单向数据流**：`TCP 连接 → SSH 握手 → 认证欺骗 → Shell/Exec Channel → 仿真执行 → 事件 → 分析/告警/存储`。所有层通过事件总线解耦，互不阻塞。

## 3. 核心模块详细设计

### 3.1 接入层（`internal/server`）

- 支持多端口监听（22/2222/22222…），每端口可绑定不同"角色"。
- 连接即记：`source_ip / sport / dport / 客户端 SSH 版本串`，作为会话指纹。
- 速率限制与并发上限（防反制：攻击者拿蜜罐跑大字典打爆内存）。
- 可选 TCP 透明转发（前置负载均衡，或把蜜罐伪装成内网资产）。

### 3.2 协议引擎（`internal/ssh`，基于 `golang.org/x/crypto/ssh`）

在标准库 SSH 服务端之上做封装，关键点：

- 自定义 `ServerConfig`：屏蔽真实指纹特征（KEX/cipher/MAC 算法表可按需裁剪，模拟 OpenSSH 8.x 常见参数）。
- **认证回调全部接管**：`PasswordCallback`、`KeyboardInteractiveCallback`、`PublicKeyCallback`、`NoClientAuth`。
- 会话 Channel 处理：`exec`、`shell`、`subsystem(sftp)` 三种请求分别路由；透传 `TERM / COLUMNS / LINES` 到终端仿真器。
- 每个连接一个 goroutine + 内部子 goroutine（读/写/控制），用 context 做全链路超时与生命周期管理。

### 3.3 认证欺骗层（`internal/auth`）

| 方法 | 策略 |
|---|---|
| `none` | 第一次回复失败，制造"服务器存在且版本真实"的错觉 |
| `password` | 查弱口令库 + 动态延迟（模拟真实密码哈希校验耗时），全部记录 |
| `keyboard-interactive` | 模拟 Linux PAM 风格的多轮问答（M2） |
| `publickey` | 解析并记录公钥指纹（M2） |

- **弱口令库**：内置常见 root/admin/test 等字典，可配置概率放行，制造高价值会话。
- **用户名枚举防护**：所有用户名统一返回失败，不做时间侧信道。

### 3.4 Shell 解释器（`internal/shell`）

高交互蜜罐的"大脑"，把原始命令串变成结构化 AST：

- 支持 `&& / || / ; / | / $() / 引号 / 通配符 / 重定向` 的解析（M2 引入 `mvdan.cc/sh/v3` 做完整语法解析）。
- **命令分类执行**：
  - 内建命令（`cd / pwd / export / alias / echo`）→ VFS 内状态变更；
  - 系统命令（`ls / cat / uname / id / ps / whoami`）→ 查 VFS 与伪装输出模板；
  - 网络命令（`ping / wget / curl / nc`）→ 交给 VNet 仿真（M2）；
  - **危险命令**（`wget|curl ... | sh`、`base64 -d`、`mkfifo ... ; nc` 等）→ 触发规则引擎（M2）。
- 每条命令记录：**原文、规范化后的 argv、exit code、输出摘要、执行耗时**。

### 3.5 虚拟文件系统（`internal/vfs`）

- 基于内存 VFS，预置**逼真的 Linux 根文件系统快照**：`/etc/passwd`、`/etc/shadow`（合成 hash）、`/proc/`、`/root/`、`/tmp/`、常见服务目录。
- 记录所有文件读写的偏移量、字节数；`/proc` 下动态内容按需生成。

### 3.6 虚拟网络（`internal/vnet`，M2）

仿真出站网络行为而**绝不真正发包**：

- `ping` → 合成 RTT；`traceroute` → 模拟跳数；
- `wget/curl` → 生成"下载中"输出，记录 URL，可返回投毒 payload；
- `nc` → 模拟连接失败或超时；记录所有连接目标，形成横向移动意图图谱。

### 3.7 终端仿真（`internal/tty`）

- 模拟 PTY：处理 ANSI 转义（光标移动、颜色、清屏、tab 补全回显）。
- **完整录制**：按键输入流 + 输出字节流 + 时间戳，存为 **ttyrec 格式**，可离线回放攻击全过程。

### 3.8 行为分析层（`internal/event` + `internal/detect`）

- **事件总线**：内存 channel 订阅/发布，事件模型统一（见 §4），低耦合、可加多消费者。
- **规则引擎**：规则 = 事件模式 + 条件 + 严重级（M2）。示例：
  - `wget|curl` 下载可疑域名；
  - 登录成功后 3 秒内执行 `whoami + uname + id`（扫描型入侵特征）；
  - `echo <base64> | base64 -d` 长度 > 1KB；
  - 修改 `authorized_keys` / `crontab`；
  - 同一 IP 5 分钟内 ≥ 50 次失败认证。
- **风险评分**：按会话累计加权分，超阈值告警（Webhook / Syslog / 邮件）。

### 3.9 存储层（`internal/store`）

- 主存储：**SQLite**（`modernc.org/sqlite`，纯 Go 免 CGO），表结构见 §4；
- 原始事件流水：**JSONL 文件**（按天分片），便于离线大数据分析；
- ttyrec 录制文件按会话 id 落盘 `data/recordings/<session_id>.ttyrec`；
- 可配导出：Syslog / CEF 对接 SIEM。

### 3.10 管理平面（`internal/config` + `internal/api`）

- YAML 配置中心：监听端口、弱口令库、放行概率、规则集、存储路径、告警通道。
- 管理 API（可选，鉴权+仅内网）：实时会话列表、命令流订阅、事件查询。
- Prometheus 指标：连接数、认证失败率、命令吞吐、告警数。

## 4. 数据模型（核心表）

```
connections     会话级元数据
  id, start_time, end_time, source_ip, source_port, target_port,
  client_version, kex_alg, cipher, status

auth_attempts   认证尝试（每次尝试一行）
  id, connection_id, ts, username, password, method,
  success, delay_ms, pubkey_fingerprint

sessions        SSH 会话通道（一个连接可开多个）
  id, connection_id, channel_type(exec/shell/subsystem),
  term, cols, rows, opened_at, closed_at

commands        命令执行
  id, session_id, ts, command, cwd,
  exit_code, duration_ms, output_preview

files           文件投递/读取（scp、sftp、echo>、wget）
  id, session_id, ts, filename, path, size, sha256, source

alerts          告警
  id, ts, connection_id, session_id, rule_name, severity, evidence
```

## 5. 目录结构

```
honeypot-go/
├── cmd/honeypot/main.go          # 入口：装配、启动、优雅退出
├── internal/
│   ├── config/                   # YAML 配置加载与校验
│   ├── server/                   # 监听、连接调度、限速
│   ├── ssh/                      # SSH 协议封装（x/crypto/ssh 二次封装）
│   ├── auth/                     # 认证欺骗
│   ├── session/                  # 会话生命周期管理
│   ├── shell/                    # shell 解析与命令执行
│   ├── vfs/                      # 虚拟文件系统
│   ├── vnet/                     # 虚拟网络命令仿真（M2）
│   ├── tty/                      # 终端仿真 + ttyrec 录制
│   ├── event/                    # 事件总线与事件模型
│   ├── detect/                   # 规则引擎、评分、告警（M2）
│   ├── store/                    # SQLite/JSONL 持久化
│   └── api/                      # 管理接口 + 遥测（M3）
├── data/                         # SQLite、ttyrec、JSONL（运行时生成）
├── configs/honeypot.yaml         # 示例配置
├── docs/                         # 架构/部署文档
└── go.mod
```

## 6. 技术选型

| 领域 | 方案 | 理由 |
|---|---|---|
| SSH 协议 | `golang.org/x/crypto/ssh` | 标准实现，服务端 channel/auth 全可控 |
| Shell 解析 | `mvdan.cc/sh/v3`（M2） | 完整 POSIX shell 语法解析，支持 AST 改写 |
| 配置 | `gopkg.in/yaml.v3` | 通用 |
| 存储 | `modernc.org/sqlite` | 纯 Go 免 CGO，单机零运维 |
| 日志 | 标准库 `log/slog` | 结构化、零依赖 |
| 遥测 | `prometheus/client_golang`（M3） | 标准生态 |

## 7. 蜜罐自身安全加固（防反制）

1. **不真实执行任何系统命令**——仿真隔离是第一道防线。
2. **出站默认全禁**：VNet 不真正发包；iptables/nftables 做黑名单策略（部署期）。
3. **进程加固**：以非 root 运行；Docker/nsjail 二次隔离（部署期）。
4. **资源限制**：每会话 CPU/内存配额、命令执行耗时上限、连接级超时，防"蜜罐跑死"。
5. **反探测**：伪装版本号与真实 OpenSSH 一致；不暴露蜜罐特征 banner。
6. **风险最小化**：蜜罐网段与生产网段隔离；监控自身进程异常。

## 8. 演进路线

- **M1 MVP（当前）**：多端口监听 + password 认证欺骗 + 弱口令放行 + 基础命令解释器（内建+常用系统命令）+ 内存 VFS + 事件入库 SQLite + ttyrec 录制。
- **M2 完善**：keyboard-interactive / publickey 伪造、`mvdan.cc/sh` 完整解析、VNet 仿真（wget/curl/ping）、SFTP 子系统仿真、规则引擎 + 风险评分 + 告警。
- **M3 强化**：多实例/蜜网编排、SIEM/CEF 导出、YARA 载荷检测、攻击链关联可视化、ML 命令异常检测。
