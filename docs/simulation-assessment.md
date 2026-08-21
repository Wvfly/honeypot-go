# 仿真能力评估报告

> 评估日期：2026-08-21
> 评估范围：honeypot-go 全模块（SSH 服务端、会话、Shell 执行器、VFS、网络仿真）
> 依据：`internal/ssh/server.go`、`internal/session/session.go`、`internal/shell/executor.go`、`internal/shell/parse.go`、`internal/vfs/vfs.go`、`internal/vnet/vnet.go`、`configs/honeypot.yaml`

---

## 一、现状评估（分层）

| 层 | 现状 | 评价 |
| --- | --- | --- |
| SSH 握手/认证 | OpenSSH 8.9 版本伪装、多认证方法、延迟模拟、弱口令概率登录 | 较好，唯一弱点：`x/crypto/ssh` 默认 kex/cipher 算法列表与 OpenSSH 8.9 有差异，高级攻击者可做算法指纹识别 |
| 交互体验 | 提示符、回显、退格、Ctrl-C/D | 弱：无 ↑ 历史键、无 Tab 补全、无行内编辑（敲 `↑` 会打印 `^[[A`） |
| 命令集 | 约 30 个内建 + 13 个网络命令 | 中：基础侦察命令有，但 `sudo`、`env`、`find`、`free`、`df`、`netstat`、`su`、`vi` 等高频命令缺失 |
| 文件系统 | 骨架较全（/etc、/proc 动态、家目录、/tmp），写入带权限校验 | 中：硬伤多（见下），内容"太干净"、时间戳单一 |
| Shell 语法 | mvdan.cc/sh 完整解析 + 展开 + 重定向 + 管道 | 较好，管道仅有界过滤语义、变量集极小 |
| 网络仿真 | ping/curl/wget/nc/dig/route 等输出逼真，事件联动完整 | 中：wget/curl 声称下载成功但文件未落盘；nc 监听立即返回 |

## 二、一敲就露馅的硬伤（优先级最高）

1. **`cd ..` 不可用** —— `resolve` 遇到 `..` 直接返回失败。任何有经验者 `cd /var/www && cd ..` 即识破，这是最严重的仿真缺陷。
2. **`$HOME` 返回 cwd** —— `expandConfig` 把 `HOME` 绑到 `cwd`，`echo $HOME` 输出 `/var/www` 而非 `/root`。
3. **↑/↓ 历史键、Tab 补全无响应** —— 交互循环只处理 `\r/\n/0x03/0x04/0x7f`，ANSI 箭头直接回显 `^[[A`，攻击者敲一下立刻识破。
4. **`ls -la` 缺 `.`/`..` 条目、时间列固定 `Jan 01 12:00`** —— 真实系统必有，且所有文件 mtime 都是 `time.Now()`，全系统同时刻创建极不自然。
5. **`history` 硬编码且不更新** —— 攻击者执行的命令不会追加进 `.bash_history`，重开会话历史丢失。
6. **`echo -n` 不支持**、`$?`/`$$`/`$PATH` 为空 —— 真实脚本依赖这些，立即暴露。
7. **`wget`/`curl` 假下载** —— 声称 "Saving to: 'x'"，但 VFS 中无此文件，`ls` 看不到。
8. **`ps`/`who` 输出固定**（PID 恒为 402/410）—— 与 `ifconfig` 的 IP 等可交叉验证，多次会话一致即破绽。

## 三、加强建议（按优先级）

### P0 硬伤修复（收益最大，工作量小）
- **VFS 支持 `..` 回溯**（resolve 携带深度计数，`..` 向父级移动）
- **环境变量修正**：`HOME=/root`、`PWD=cwd`，补齐 `$?`/`$$`/`$PATH`/`$LANG`
- **交互增强**：解析 CSI 序列（`↑`/`↓` 查历史、`←`/`→` 行内编辑、`Tab` 基于 VFS 的路径补全）、`history` 实时追加
- **ls 补 `.`/`..`、多路径参数、mtime 渲染**，VFS 各文件 `mtime` 错开（bootstrap 时按随机偏移设置）

### P1 高频侦察命令补齐
`env`/`export`/`set`、`which`、`uptime`、`free`、`df`、`mount`、`sudo -l`（伪装已配置 sudo）、`su`、`find`、`netstat -tlnp`/`ss`、`arp -a`、`last`/`lastlog`/`w`、`kill`、`jobs`、`touch`/`mkdir`/`rm`/`mv`/`cp`/`chmod`/`chown`、`base64`、`sha256sum`/`md5sum`、`awk`/`sed`/`cut`/`tr`、`file`/`stat`/`du`。其中 `base64 -d`、`sha256sum`、`netstat` 是攻击者下载/落地/横向探测链的关键环节，仿真输出能显著拉长交互。

### P2 文件系统真实度
- 补齐 `/root/.ssh/authorized_keys`、`.bashrc`/`.profile`、`/var/log`（syslog、dpkg.log、wtmp）、`/etc`（nginx/sites-enabled、ssh/sshd_config、ufw、crontab）、`/proc/self/status`、`/proc/net/tcp`
- 权限/属主细化（当前清一色 root:root + 固定权限），`/home/ubuntu` 内容补全
- `/etc/shadow` 哈希与"成功登录"用户关联

### P3 行为与输出仿真
- 命令执行加毫秒级随机延迟（模拟真实磁盘/CPU）
- `ls --color`/`grep --color` 可选着色、`printf`、`echo -n`
- wget/curl 落盘真实写入 VFS（复用现有 `WriteFile` 的大小上限与权限校验），nc 监听模式延迟数秒再报超时

### P4 网络仿真
- `netstat -tlnp`/`ss` 输出与 `ps` 进程表联动（端口 ↔ PID ↔ 进程名一致，跨命令交叉验证）
- `ping -c N` 尊重参数、`dig` 支持 A/MX 记录类型、新增 `hostname -I`/`ip route`

## 四、建议执行顺序

**P0 的 1–4 项**：一次小改动即可消除最显眼破绽 → **P1 补命令**（防御价值最高，能收集更多攻击行为事件）→ **P2–P4** 提升长期可信度。

---

## 五、实施记录（2026-08-21，已按 P0→P4 完成）

> 全程约束：新增功能不引入真实系统调用；所有写操作走 VFS 权限校验；输出/遍历/历史/下载均有上限，防 DoS；每步 `go build ./... && go vet ./...` 通过。

### P0 硬伤修复 ✅
- VFS `walkPath` 显式栈支持 `..` 回溯（根目录 `..` 仍为根）；`ls` 多路径、`-A`、`.`/`..` 条目、mtime 按年份渲染
- `$HOME`/`$PATH`/`$LANG`/`$?`/`$$`/`$#` 注入 `FuncEnviron`（`?` 键 = lastCode，`$` 键 = 会话 PID）
- 交互循环解析 CSI（↑↓←→/Home/End/Del）、Tab 补全（VFS 驱动，候选 ≤24）、`history` 实时追加（会话隔离，上限 200）
- `echo -n`、`printf`（占位符转义，缺参不崩）

### P1 高频命令补齐 ✅
- VFS 写 API：`Mkdir`/`Remove`/`RemoveAll`/`Rename`/`Copy`（不覆盖）/`Chmod`/`Chown`/`Touch`，均校验父目录可写
- 命令：`env`/`which`/`uptime`/`sudo -l`/`find`（限 500 行）/`touch`/`mkdir`/`rm`/`mv`/`cp`/`chmod`/`chown`/`file`/`stat`/`du`
- 过滤链扩展至 18 种（awk/sed/cut/tr/base64/tee/xargs/sha256sum/md5sum 等），`tee` 落盘复用 `WriteFile`

### P2 文件系统真实度 ✅
- bootstrap 扩充：`/proc`（version/cpuinfo/meminfo/uptime/loadavg/stat/self/*/net/*）、`/etc/ssh/sshd_config`、`/etc/nginx/*`、`/etc/ufw`、`/etc/group`、`/etc/crontab`、`/var/log/*`、`/root/.ssh`、`/home/ubuntu/*`、`/var/www`、`/srv`、`/var/tmp`、`/dev/shm`、`/tmp`
- 修复隐藏 bug：`/proc` 节点原未创建导致 `procContent` 动态内容死代码
- mtime 错开：`fakeMtime` 按路径 FNV 哈希生成 1~90 天前历史时间

### P3 行为与输出仿真 ✅
- `simDelay`：按命令类别毫秒级随机延迟（重命令 ≤250ms / 常规 ≤80ms / 轻命令 ≤25ms），上限防 DoS
- `ls --color[=always|auto|never]`：目录蓝/可执行绿/链接青/隐藏暗灰 ANSI 着色（仅显示层，不改 VFS）
- `wget`/`curl` 真实落盘：内容按扩展名生成（固定 1234 字节），经 VFS `WriteFile` 父目录可写校验；`safeDownloadPath` 拒绝 `..` 段防写穿；curl 无 `-o` 时 body 输出 stdout；下载事件照常上报
- 修复 `/tmp` 缺失导致 `echo > /tmp/x`、`curl -o /tmp/...` 失败

### P4 网络仿真 ✅
- `netstat` 动态化：LISTEN 行与 ps 进程表联动（sshd 378/nginx 815/mysqld 920），非 `-l` 模式追加动态 ESTABLISHED 连接（本机 IP 与 ifconfig 一致 10.0.2.15）
- `ping -c N`：尊重 `-c` 且上限 16 包（`maxPingCount`，防 `-c 999999` 的 200ms/包 sleep 拖死会话）；修复 `-c 5` 取值被误判为目标
- `dig` 查询类型：A/AAAA/MX/TXT/NS/CNAME/SOA/PTR/SRV/ANY（`-t TYPE` 与 `dig host MX` 均支持）；修复命令名被误当目标
- `hostname -I`/`-i` 输出 10.0.2.15

### 未实施项（低价值/可选）
- `grep --color` 着色、nc 监听模式延迟数秒超时、`su`/`vi`/`jobs`/`kill`、SSH kex 算法指纹伪装、`/etc/shadow` 哈希与登录用户强关联
