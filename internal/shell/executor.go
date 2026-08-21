package shell

import (
	"fmt"
	"hash/fnv"
	"log/slog"
	"math/rand/v2"
	"path"
	"strconv"
	"strings"
	"sync"
	"time"

	"honeypot-go/internal/event"
	"honeypot-go/internal/vfs"
	"honeypot-go/internal/vnet"
)

// Executor 命令执行器：解析命令串并仿真执行，输出与真实系统相似的结果。
// M2 支持：完整 shell 语法（引号/通配符/命令替换/管道/重定向）+ 虚拟网络命令。
type Executor struct {
	fs       *vfs.FileSystem
	bus      *event.Bus
	hostname string
	logger   *slog.Logger
	vnet     *vnet.VNet

	// 会话级状态（跨 Execute 保留）：上次退出码、命令历史。
	// 由 sessionID 隔离，锁保护；会话关闭时经 RemoveSession 清理防内存泄漏。
	stMu   sync.Mutex
	states map[string]*sessionState

	// 会话 cwd 快照：供 vnet 的 wget/curl 落盘解析相对路径。
	cwdMu  sync.Mutex
	cwdMap map[string]string
}

// sessionState 单个会话的跨命令状态
type sessionState struct {
	lastCode int
	history  []string
}

// execCtx 单次 Execute 的执行上下文：承载会话 ID、命令替换/子 shell 嵌套深度、
// 上次退出码与 shell PID。每次 Execute 独立创建，仅在同一 goroutine 内同步使用。
type execCtx struct {
	sessionID string
	depth     int
	lastCode  int
	pid       string
}

// maxCmdSubstDepth 命令替换/子 shell 最大嵌套深度：防深嵌套展开耗尽栈与 CPU。
const maxCmdSubstDepth = 32

// Result 一次命令执行的结果
type Result struct {
	Output []byte
	Code   int
}

// New 创建执行器
func New(fs *vfs.FileSystem, bus *event.Bus, hostname string, logger *slog.Logger) *Executor {
	e := &Executor{
		fs:       fs,
		bus:      bus,
		hostname: hostname,
		logger:   logger,
		vnet:     vnet.New(bus, logger),
		states:   map[string]*sessionState{},
		cwdMap:   map[string]string{},
	}
	// wget/curl 下载内容落盘到虚拟文件系统（经 WriteFile 的父目录可写/大小上限校验）
	e.vnet.SetDownload(e.fs.WriteFile, e.cwdFor)
	return e
}

// cwdFor 返回某会话最近一次执行的 cwd（供 vnet 下载落盘解析相对路径）
func (e *Executor) cwdFor(sessionID string) string {
	e.cwdMu.Lock()
	defer e.cwdMu.Unlock()
	return e.cwdMap[sessionID]
}

// setCWD 记录会话当前 cwd（Execute 入口调用，覆盖旧值）
func (e *Executor) setCWD(sessionID, cwd string) {
	e.cwdMu.Lock()
	defer e.cwdMu.Unlock()
	e.cwdMap[sessionID] = cwd
}

// maxSessionHistory 单会话命令历史上限：防会话长期运行导致内存无限增长
const maxSessionHistory = 200

// RemoveSession 清理会话级状态（lastCode/history/cwd），会话关闭时调用
func (e *Executor) RemoveSession(sessionID string) {
	e.stMu.Lock()
	delete(e.states, sessionID)
	e.stMu.Unlock()
	e.cwdMu.Lock()
	delete(e.cwdMap, sessionID)
	e.cwdMu.Unlock()
}

// AddHistory 追加一条命令到会话历史（去空、去连续重复、超上限丢弃最旧）
func (e *Executor) AddHistory(sessionID, cmd string) {
	if strings.TrimSpace(cmd) == "" {
		return
	}
	e.stMu.Lock()
	defer e.stMu.Unlock()
	st := e.states[sessionID]
	if st == nil {
		st = &sessionState{}
		e.states[sessionID] = st
	}
	if len(st.history) > 0 && st.history[len(st.history)-1] == cmd {
		return
	}
	if len(st.history) >= maxSessionHistory {
		st.history = st.history[1:]
	}
	st.history = append(st.history, cmd)
}

// History 返回会话命令历史的拷贝
func (e *Executor) History(sessionID string) []string {
	e.stMu.Lock()
	defer e.stMu.Unlock()
	if st := e.states[sessionID]; st != nil {
		return append([]string(nil), st.history...)
	}
	return nil
}

// sessionPid 基于会话 ID 生成稳定的伪 shell PID（1000~60000），跨命令一致、会话间不同
func sessionPid(sessionID string) string {
	h := fnv.New32a()
	h.Write([]byte(sessionID))
	return strconv.Itoa(int(h.Sum32()%49000) + 2000)
}

// maxOutputSize 单命令合并输出上限：防 cat 大文件 / 命令叠加把输出缓冲、channel 写入与 ttyrec 录制撑爆
const maxOutputSize = 8 << 20 // 8 MiB

// truncSuffix 输出截断时追加的提示
var truncSuffix = []byte("\n...(output truncated)\n")

// limitOutput 将输出截断到 maxOutputSize，超出部分丢弃并在末尾追加提示
func limitOutput(out []byte) []byte {
	if len(out) <= maxOutputSize {
		return out
	}
	truncated := make([]byte, maxOutputSize+len(truncSuffix))
	copy(truncated, out[:maxOutputSize])
	copy(truncated[maxOutputSize:], truncSuffix)
	return truncated
}

// capOut 中间输出软上限：多命令串联（; && || |）时 out 会逐段累积传给下一条命令，
// 若不截断，N 段命令可把 out 撑到 N×8MiB 才在最外层 limitOutput 截断，造成内存放大。
// 语义与 limitOutput 一致（保留前缀），但不追加提示（最外层统一加），且仅在超限时复制。
func capOut(out []byte) []byte {
	if len(out) <= maxOutputSize {
		return out
	}
	return out[:maxOutputSize]
}

// simDelay 仿真命令执行耗时：按命令类别给毫秒级随机延迟。
// 上限固定（重命令 250ms / 常规 80ms / 轻命令 25ms），防大量命令导致 CPU 与交互排队膨胀。
func simDelay(bin string) {
	maxMs := 25
	switch bin {
	case "find", "du", "grep", "egrep", "fgrep", "awk", "sed", "sort",
		"tar", "gzip", "gunzip", "apt", "apt-get", "yum", "dnf", "make":
		maxMs = 250
	case "cat", "head", "tail", "wc", "file", "stat", "ps", "free", "df",
		"mount", "ifconfig", "ip", "route", "netstat", "ss", "wget", "curl",
		"traceroute", "ping", "dig", "nslookup", "host", "python", "python3",
		"perl", "php", "ruby", "java", "git", "ssh", "scp", "rsync":
		maxMs = 80
	}
	if maxMs > 0 {
		time.Sleep(time.Duration(rand.IntN(maxMs)+1) * time.Millisecond)
	}
}

// Execute 执行一段命令串（可含 ; && || | $()），返回最终 exit code 与合并输出。
// 返回执行后的新 cwd（支持 cd 状态变更）。
func (e *Executor) Execute(sessionID, cwd, raw string) (string, Result) {
	return e.executeDepth(sessionID, cwd, raw, 0)
}

// executeDepth 带嵌套深度的执行入口：sudo 等内部重入通过 depth 复用
// maxCmdSubstDepth 上限，防止 sudo sudo ... 无限递归耗尽栈与 CPU。
func (e *Executor) executeDepth(sessionID, cwd, raw string, depth int) (string, Result) {
	ctx := &execCtx{sessionID: sessionID, pid: sessionPid(sessionID), depth: depth}
	e.setCWD(sessionID, cwd)

	start := time.Now()
	var (
		newCwd string
		code   int
		output []byte
		ok     bool
	)
	e.stMu.Lock()
	if st := e.states[sessionID]; st != nil {
		ctx.lastCode = st.lastCode
	}
	e.stMu.Unlock()
	newCwd, code, output, ok = e.runAST(ctx, cwd, raw)
	if !ok {
		// AST 解析失败（非常规语法），fallback 到旧的轻量解析
		newCwd, code, output = e.runSequence(ctx, cwd, raw)
	}
	output = limitOutput(output)
	// 回写会话级上次退出码，供下一条命令的 $? 使用
	e.stMu.Lock()
	st := e.states[sessionID]
	if st == nil {
		st = &sessionState{}
		e.states[sessionID] = st
	}
	st.lastCode = code
	e.stMu.Unlock()
	res := Result{Output: output, Code: code}

	e.bus.Publish(event.New(event.TypeCommandExecuted, map[string]any{
		"session_id":     sessionID,
		"command":        raw,
		"cwd":            cwd,
		"exit_code":      code,
		"duration_ms":    time.Since(start).Milliseconds(),
		"output_preview": preview(output),
	}))
	return newCwd, res
}

// runSequence 按 ; 和 && / || 拆分执行序列，返回新 cwd
func (e *Executor) runSequence(ctx *execCtx, cwd, raw string) (string, int, []byte) {
	var out []byte
	code := 0
	for _, seg := range splitTopLevel(raw, ';') {
		seg = strings.TrimSpace(seg)
		if seg == "" {
			continue
		}
		cwd, code, out = e.runAndOr(ctx, cwd, seg, out)
		out = capOut(out) // 中间软上限：防多段命令 out 无限累积放大内存
	}
	return cwd, code, out
}

func (e *Executor) runAndOr(ctx *execCtx, cwd, seg string, out []byte) (string, int, []byte) {
	tokens := splitLogical(seg)
	if len(tokens) == 0 {
		return cwd, 0, out
	}
	code := 0
	for _, t := range tokens {
		cmd := strings.TrimSpace(t.cmd)
		if cmd == "" {
			continue
		}
		var c int
		cwd, c, out = e.execPipeline(ctx, cwd, cmd, out)
		out = capOut(out) // 中间软上限：防 &&/|| 链 out 无限累积放大内存
		if t.op == "&&" && c != 0 {
			return cwd, c, out
		}
		if t.op == "||" && c == 0 {
			return cwd, 0, out
		}
		code = c
	}
	return cwd, code, out
}

func (e *Executor) execPipeline(ctx *execCtx, cwd, cmd string, out []byte) (string, int, []byte) {
	cmds := splitTopLevel(cmd, '|')
	if len(cmds) == 1 {
		args := tokenize(strings.TrimSpace(cmds[0]))
		if len(args) == 0 {
			return cwd, 0, out
		}
		return e.execOne(ctx, cwd, args, out)
	}
	// 管道：M1 简化——按顺序执行，合并输出
	code := 0
	for _, c := range cmds {
		args := tokenize(strings.TrimSpace(c))
		if len(args) == 0 {
			continue
		}
		cwd, code, out = e.execOne(ctx, cwd, args, out)
	}
	return cwd, code, out
}

// execOne 执行单条命令，返回新 cwd
func (e *Executor) execOne(ctx *execCtx, cwd string, args []string, out []byte) (string, int, []byte) {
	bin := args[0]
	// 支持 /bin/ls 这类带路径形式
	if i := strings.LastIndex(bin, "/"); i >= 0 {
		bin = bin[i+1:]
	}
	rest := args[1:]

	// M2: 虚拟网络命令（ping/curl/wget/nc 等），仿真出站、记录目标
	normArgs := append([]string{bin}, rest...)
	if ob, code, handled := e.vnet.Exec(ctx.sessionID, normArgs); handled {
		return cwd, code, append(out, ob...)
	}

	// 仿真命令执行耗时：真实 shell 每条命令都有可感知延迟，随机等待使交互节奏更逼真
	simDelay(bin)

	switch bin {
	case "cd":
		if len(rest) == 0 {
			return cwd, 0, append(out, []byte(cwd+"\n")...)
		}
		target := rest[0]
		if !strings.HasPrefix(target, "/") {
			target = joinPath(cwd, target)
		}
		if !e.fs.IsDir(target) {
			return cwd, 1, append(out, []byte("bash: cd: "+rest[0]+": No such file or directory\n")...)
		}
		return target, 0, out
	case "pwd":
		return cwd, 0, append(out, []byte(cwd+"\n")...)
	case "echo":
		line := strings.Join(rest, " ")
		if len(rest) == 0 || rest[0] != "-n" {
			line += "\n"
		} else {
			line = strings.Join(rest[1:], " ")
		}
		return cwd, 0, append(out, []byte(line)...)
	case "printf":
		return cwd, 0, append(out, e.printf(rest)...)
	case "hostname":
		// hostname -I / -i 显示本机仿真 IP（与 ifconfig/ip addr/arp 一致）
		if len(rest) == 1 && (rest[0] == "-I" || rest[0] == "-i" || rest[0] == "--all-ip-addresses") {
			return cwd, 0, append(out, []byte("10.0.2.15\n")...)
		}
		return cwd, 0, append(out, []byte(e.hostname+"\n")...)
	case "whoami":
		return cwd, 0, append(out, []byte("root\n")...)
	case "id":
		return cwd, 0, append(out, []byte("uid=0(root) gid=0(root) groups=0(root)\n")...)
	case "date":
		return cwd, 0, append(out, []byte(time.Now().Format("Mon Jan 02 15:04:05 UTC 2006")+"\n")...)
	case "uname":
		return cwd, 0, append(out, e.uname(rest)...)
	case "ls":
		return cwd, 0, append(out, e.ls(cwd, rest)...)
	case "cat":
		if len(rest) == 0 {
			return cwd, 1, append(out, []byte("Usage: cat [OPTION]... [FILE]...\n")...)
		}
		for _, f := range rest {
			path := f
			if !strings.HasPrefix(path, "/") {
				path = joinPath(cwd, f)
			}
			content, err := e.fs.ReadFile(path)
			if err != nil {
				out = append(out, []byte("cat: "+f+": No such file or directory\n")...)
				continue
			}
			out = append(out, content...)
		}
		return cwd, 0, out
	case "ps":
		return cwd, 0, append(out, e.ps(rest)...)
	case "who":
		return cwd, 0, append(out, []byte("root     pts/0        "+time.Now().Format("2006-01-02 15:04")+" (10.0.2.15)\n")...)
	case "clear":
		return cwd, 0, append(out, []byte("\x1b[H\x1b[2J")...)
	case "history":
		hist := e.History(ctx.sessionID)
		var hb strings.Builder
		if len(hist) == 0 {
			hb.WriteString("    1  ls -la\n    2  whoami\n    3  cat /etc/passwd\n")
		} else {
			for i, c := range hist {
				fmt.Fprintf(&hb, "%5d  %s\n", i+1, c)
			}
		}
		return cwd, 0, append(out, []byte(hb.String())...)
	case "true":
		return cwd, 0, out
	case "false":
		return cwd, 1, out
	case "exit", "logout":
		return cwd, 0, out
	case "grep", "egrep", "fgrep", "head", "tail", "wc", "sort", "uniq", "awk", "sed", "cut", "tr", "base64", "strings", "tee", "xargs", "sha256sum", "md5sum":
		return cwd, 0, append(out, e.filterCmd(cwd, bin, rest)...)
	case "env":
		return cwd, 0, append(out, e.envCmd(cwd)...)
	case "export":
		// 仿真：export FOO=bar 静默成功（会话内保留留待后续增强）
		return cwd, 0, out
	case "set":
		return cwd, 0, append(out, e.envCmd(cwd)...)
	case "which":
		return cwd, 0, append(out, e.whichCmd(rest)...)
	case "uptime":
		return cwd, 0, append(out, e.uptimeCmd()...)
	case "free":
		return cwd, 0, append(out, []byte(freeText)...)
	case "df":
		return cwd, 0, append(out, []byte(dfText)...)
	case "mount":
		return cwd, 0, append(out, []byte(mountText)...)
	case "sudo":
		return cwd, 0, append(out, e.sudoCmd(ctx, cwd, rest)...)
	case "su":
		return cwd, 0, append(out, []byte("su: Authentication failure\n")...)
	case "find":
		return cwd, 0, append(out, e.findCmd(cwd, rest)...)
	case "netstat":
		return cwd, 0, append(out, netstatCmd(rest)...)
	case "ss":
		return cwd, 0, append(out, []byte(ssText)...)
	case "arp":
		return cwd, 0, append(out, []byte(arpText)...)
	case "last":
		return cwd, 0, append(out, []byte(lastText)...)
	case "lastlog":
		return cwd, 0, append(out, []byte(lastlogText)...)
	case "w":
		return cwd, 0, append(out, e.wText()...)
	case "kill", "jobs", "ln":
		return cwd, 0, out
	case "touch":
		return cwd, 0, append(out, e.touchCmd(cwd, rest)...)
	case "mkdir", "rmdir":
		return cwd, 0, append(out, e.mkdirCmd(cwd, rest)...)
	case "rm":
		return cwd, 0, append(out, e.rmCmd(cwd, rest)...)
	case "mv":
		return cwd, 0, append(out, e.mvCmd(cwd, rest)...)
	case "cp":
		return cwd, 0, append(out, e.cpCmd(cwd, rest)...)
	case "chmod":
		return cwd, 0, append(out, e.chmodCmd(cwd, rest)...)
	case "chown":
		return cwd, 0, append(out, e.chownCmd(cwd, rest)...)
	case "file":
		return cwd, 0, append(out, e.fileCmd(cwd, rest)...)
	case "stat":
		return cwd, 0, append(out, e.statCmd(cwd, rest)...)
	case "du":
		return cwd, 0, append(out, e.duCmd(cwd, rest)...)
	// 常用脚本解释器：sh/bash/python/perl 等。攻击者常用 -c/-e 内联代码执行
	// 反弹 shell 或下载载荷。蜜罐不真实执行，但需"假装成功"（exit 0，无输出），
	// 并将内联代码递归执行一次，使 wget/curl/重定向等副作用落入 VFS 与 vnet 检测。
	case "sh", "bash", "dash", "ash", "ksh", "zsh":
		nc, c, o := e.runInterpreter(ctx, cwd, bin, rest, out)
		return nc, c, o
	case "python", "python3", "python2", "perl", "php", "ruby", "lua", "node":
		nc, c, o := e.runInterpreter(ctx, cwd, bin, rest, out)
		return nc, c, o
	default:
		out = append(out, []byte("bash: "+args[0]+": command not found\n")...)
		return cwd, 127, out
	}
}

// runInterpreter 仿真解释器执行：提取 -c/-e 内联代码并递归执行一次（使副作用落入
// VFS/vnet 检测），但丢弃其输出与 cwd 变更（解释器子进程不影响父 shell）。
// 无内联代码（交互模式/脚本文件路径）时静默成功。嵌套超限时返回错误提示，防递归 DoS。
func (e *Executor) runInterpreter(ctx *execCtx, cwd, bin string, args []string, out []byte) (string, int, []byte) {
	code := interpreterCode(args)
	if code == "" {
		return cwd, 0, out
	}
	if ctx.depth >= maxCmdSubstDepth {
		return cwd, 1, append(out, []byte(bin+": too many nested interpreter levels\n")...)
	}
	_, _ = e.executeDepth(ctx.sessionID, cwd, code, ctx.depth+1)
	return cwd, 0, out
}

// interpreterCode 提取解释器内联代码：
//
//	-c <code>（sh/bash/python）、-e/-E <code>（perl/ruby）及 -cxxx 连写形式。
//
// 首个非选项参数（脚本文件路径）或无可提取代码时返回 ""，调用方静默成功。
func interpreterCode(args []string) string {
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "-c" || a == "-e" || a == "-E":
			if i+1 < len(args) {
				return args[i+1]
			}
			return ""
		case strings.HasPrefix(a, "-c") && len(a) > 2:
			return a[2:]
		case strings.HasPrefix(a, "-e") && len(a) > 2:
			return a[2:]
		case strings.HasPrefix(a, "-"):
			continue
		default:
			// 首个非选项参数是脚本文件路径：无内联代码
			return ""
		}
	}
	return ""
}

func (e *Executor) uname(args []string) []byte {
	all := false
	flags := map[byte]bool{}
	for _, a := range args {
		if a == "-a" {
			all = true
		} else if strings.HasPrefix(a, "-") && len(a) > 1 {
			for _, c := range a[1:] {
				flags[byte(c)] = true
			}
		}
	}
	parts := []string{"Linux", e.hostname, "5.15.0-91-generic", "#101-Ubuntu SMP Tue Nov 14 13:30:08 UTC 2023", "x86_64", "x86_64", "x86_64", "GNU/Linux"}
	if all {
		return []byte(strings.Join(parts, " ") + "\n")
	}
	var out []string
	if flags['n'] {
		out = append(out, e.hostname)
	}
	if flags['r'] {
		out = append(out, "5.15.0-91-generic")
	}
	if flags['m'] {
		out = append(out, "x86_64")
	}
	if flags['s'] || len(flags) == 0 {
		out = append(out, "Linux")
	}
	if len(out) == 0 {
		return []byte("\n")
	}
	return []byte(strings.Join(out, " ") + "\n")
}

func (e *Executor) ls(cwd string, args []string) []byte {
	var paths []string
	showAll := false
	long := false
	color := false
	for _, a := range args {
		switch {
		case a == "-a" || a == "-la" || a == "-al":
			showAll, long = true, true
		case a == "-l":
			long = true
		case a == "-A":
			showAll = true
		case a == "--color" || a == "--color=always" || a == "--color=auto":
			color = true
		case a == "--color=never":
			color = false
		case strings.HasPrefix(a, "-"):
			// 忽略其他选项（-h -t -r 等），保持输出稳定
		default:
			paths = append(paths, a)
		}
	}
	if len(paths) == 0 {
		paths = []string{cwd}
	}
	var b strings.Builder
	for i, p := range paths {
		full := p
		if !strings.HasPrefix(full, "/") {
			full = joinPath(cwd, full)
		}
		infos, err := e.fs.List(full)
		if err != nil {
			// 参数可能是文件本身（ls /etc/passwd）
			if fi, ok := e.fs.Resolve(full); ok {
				if len(paths) > 1 {
					fmt.Fprintf(&b, "%s:\n", p)
				}
				b.WriteString(formatLsEntryNamed(fi, lsColorName(fi, fi.Name, color)) + "\n")
				continue
			}
			fmt.Fprintf(&b, "ls: cannot access '%s': No such file or directory\n", p)
			continue
		}
		if len(paths) > 1 {
			fmt.Fprintf(&b, "%s:\n", p)
		}
		if !long {
			var names []string
			if showAll {
				// 空目录下 "." ".." 仍按目录渲染：用零值 FileInfo（IsDir=false），
				// 颜色前缀由 display 决定，避免 infos[0] 越界
				var dotFI vfs.FileInfo
				if len(infos) > 0 {
					dotFI = infos[0]
				}
				names = append(names, lsColorName(dotFI, ".", color))
				names = append(names, lsColorName(dotFI, "..", color))
			}
			for _, f := range infos {
				if strings.HasPrefix(f.Name, ".") && !showAll {
					continue
				}
				names = append(names, lsColorName(f, f.Name, color))
			}
			b.WriteString(strings.Join(names, "  ") + "\n")
		} else {
			if showAll {
				if dot, ok := e.fs.Resolve(full); ok {
					b.WriteString(formatLsEntryNamed(dot, lsColorName(dot, ".", color)) + "\n")
				}
				if dd, ok := e.fs.Resolve(path.Join(full, "..")); ok {
					b.WriteString(formatLsEntryNamed(dd, lsColorName(dd, "..", color)) + "\n")
				}
			}
			for _, f := range infos {
				if strings.HasPrefix(f.Name, ".") && !showAll {
					continue
				}
				b.WriteString(formatLsEntryNamed(f, lsColorName(f, f.Name, color)) + "\n")
			}
		}
		if i < len(paths)-1 {
			b.WriteString("\n")
		}
	}
	return []byte(b.String())
}

// lsColorName 按 ls --color 规范给名称着色（仅显示名，不改变文件本身）：
// 目录粗体蓝、符号链接粗体青、可执行粗体绿、隐藏文件暗灰。
func lsColorName(f vfs.FileInfo, display string, color bool) string {
	if !color {
		return display
	}
	prefix := ""
	switch {
	case f.IsDir:
		prefix = "\x1b[01;34m"
	case strings.HasPrefix(f.Perm, "l"):
		prefix = "\x1b[01;36m"
	case strings.Contains(f.Perm, "x"):
		prefix = "\x1b[01;32m"
	case strings.HasPrefix(display, "."):
		prefix = "\x1b[01;30m"
	}
	if prefix == "" {
		return display
	}
	return prefix + display + "\x1b[0m"
}

// formatLsEntry 渲染单个 ls -l 条目：权限/属主/大小/修改时间（当年不显年份，往年显示年份）
func formatLsEntry(f vfs.FileInfo, long bool) string {
	return formatLsEntryNamed(f, f.Name)
}

// formatLsEntryNamed 用指定名称渲染条目（用于 "." 与 ".."）
func formatLsEntryNamed(f vfs.FileInfo, name string) string {
	size := f.Size
	if f.IsDir {
		size = 4096
	}
	mtime := f.Mtime
	if mtime.IsZero() {
		mtime = time.Now()
	}
	var ts string
	if mtime.Year() == time.Now().Year() {
		ts = mtime.Format("Jan 02 15:04")
	} else {
		ts = mtime.Format("Jan 02  2006")
	}
	return fmt.Sprintf("%s %s %s %8d %s %s", f.Perm, f.Owner, f.Group, size, ts, name)
}

// printf 简化实现：支持 %s/%d/%x/%f 等常见格式与 \n \t 转义。
// 使用 Go 的 fmt 安全处理：多余参数被忽略、缺失参数输出 %!(NOVERB)，不会越界或崩溃。
func (e *Executor) printf(args []string) []byte {
	if len(args) == 0 {
		return nil
	}
	format := args[0]
	// 转义处理：printf 的 \n \t 由 shell 内建解释，Go 的 Sprintf 不做，先替换占位再还原
	escaped := strings.NewReplacer(
		`\n`, "\x00N\x00", `\t`, "\x00T\x00", `\\`, "\x00S\x00",
	).Replace(format)
	var vals []any
	for _, a := range args[1:] {
		vals = append(vals, a)
	}
	out := fmt.Sprintf(escaped, vals...)
	out = strings.NewReplacer(
		"\x00N\x00", "\n", "\x00T\x00", "\t", "\x00S\x00", "\\",
	).Replace(out)
	return []byte(out)
}

// --- P1 高频侦察命令 ---

// envCmd 输出标准环境（与 expandConfig 保持一致）
func (e *Executor) envCmd(cwd string) []byte {
	return []byte(fmt.Sprintf("HOME=/root\nHOSTNAME=%s\nLANG=en_US.UTF-8\nLOGNAME=root\n"+
		"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin\nPWD=%s\n"+
		"SHELL=/bin/bash\nTERM=xterm-256color\nUSER=root\n", e.hostname, cwd))
}

// knownPaths 常见命令 → 可执行路径（仿真 which）
var knownPaths = map[string]string{
	"bash": "/usr/bin/bash", "sh": "/bin/sh", "ls": "/usr/bin/ls", "cat": "/usr/bin/cat",
	"cd": "shell builtin", "pwd": "shell builtin", "echo": "shell builtin", "grep": "/usr/bin/grep",
	"find": "/usr/bin/find", "ps": "/usr/bin/ps", "netstat": "/usr/bin/netstat", "ss": "/usr/sbin/ss",
	"curl": "/usr/bin/curl", "wget": "/usr/bin/wget", "nc": "/usr/bin/nc", "ncat": "/usr/bin/ncat",
	"python3": "/usr/bin/python3", "python": "/usr/bin/python", "perl": "/usr/bin/perl",
	"nano": "/usr/bin/nano", "vim": "/usr/bin/vim", "vi": "/usr/bin/vi", "tmux": "/usr/bin/tmux",
	"screen": "/usr/bin/screen", "chmod": "/usr/bin/chmod", "chown": "/usr/bin/chown",
	"base64": "/usr/bin/base64", "tar": "/usr/bin/tar", "apt": "/usr/bin/apt",
}

// whichCmd 仿真 which：返回命令路径；未找到 exit 1（无输出）
func (e *Executor) whichCmd(args []string) []byte {
	var b strings.Builder
	found := false
	for _, a := range args {
		if strings.HasPrefix(a, "-") {
			continue
		}
		if p, ok := knownPaths[a]; ok {
			b.WriteString(p + "\n")
			found = true
		}
	}
	if !found {
		return nil
	}
	return []byte(b.String())
}

// uptimeCmd 仿真 uptime（系统运行 7 天）
func (e *Executor) uptimeCmd() []byte {
	now := time.Now()
	return []byte(fmt.Sprintf(" %s up 7 days,  1 user,  load average: 0.00, 0.01, 0.05\n", now.Format("15:04:05")))
}

// freeText 仿真 free（16GB 内存主机）
const freeText = `              total        used        free      shared  buff/cache   available
Mem:        16345628     4567128    8674300      102400     3104200    10626456
Swap:        2097148           0    2097148
`

// dfText 仿真 df
const dfText = `Filesystem     1K-blocks     Used Available Use% Mounted on
/dev/sda1      104755200 25589148  73902628  26% /
tmpfs           8172812       176   8172636   1% /dev/shm
/dev/sda2      524032000 389034120 108070856  79% /var
`

// mountText 仿真 mount
const mountText = `/dev/sda1 on / type ext4 (rw,relatime,errors=remount-ro)
/dev/sda2 on /var type ext4 (rw,relatime)
proc on /proc type proc (rw,nosuid,nodev,noexec,relatime)
tmpfs on /dev/shm type tmpfs (rw,nosuid,nodev)
`

// sudoCmd 仿真 sudo：-l 列出权限；其余参数以 root 递归执行（有限递归，无死循环风险）
func (e *Executor) sudoCmd(ctx *execCtx, cwd string, args []string) []byte {
	if len(args) == 0 {
		return []byte("usage: sudo [-D level] -h | -K | -k | -V\n")
	}
	if args[0] == "-l" || args[0] == "--list" {
		return []byte(fmt.Sprintf(`Matching Defaults entries for root on %s:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User root may run the following commands on %s:
    (ALL : ALL) ALL
`, e.hostname, e.hostname))
	}
	if args[0] == "-i" || args[0] == "-s" || args[0] == "-u" {
		return nil
	}
	// sudo <cmd>：一次性剥离所有连续 sudo 前缀（sudo sudo ls -> ls），
	// 避免逐层递归；深度超过 maxCmdSubstDepth 直接拒绝，防 sudo sudo ... 无限嵌套 DoS。
	sub := stripLeadingSudo(strings.TrimSpace(strings.Join(args, " ")))
	if sub == "" {
		return nil
	}
	if ctx.depth >= maxCmdSubstDepth {
		return []byte("sudo: too many levels of nested sudo\n")
	}
	_, res := e.executeDepth(ctx.sessionID, cwd, sub, ctx.depth+1)
	return res.Output
}

// stripLeadingSudo 去掉命令串开头所有连续的 "sudo" 前缀（含空白）。
// "sudo sudo ls" -> "ls"；"sudo -l" -> "sudo -l"（保留 sudo 选项给递归处理）。
func stripLeadingSudo(s string) string {
	for {
		t := strings.TrimSpace(s)
		if t == "sudo" {
			return ""
		}
		// 必须是独立单词 "sudo " 开头（后随空白），避免误剥 "sudosomething"
		if !strings.HasPrefix(t, "sudo ") {
			return t
		}
		rest := strings.TrimSpace(t[len("sudo "):])
		if rest == "" {
			return ""
		}
		// 下一个 token 是 sudo 选项（-...）时停止剥离，交给递归执行处理
		if strings.HasPrefix(rest, "-") {
			return t
		}
		s = rest
	}
}

// findCmd 仿真 find：支持 -name（通配符）/ -type / -maxdepth
func (e *Executor) findCmd(cwd string, args []string) []byte {
	roots := []string{}
	namePattern := ""
	useType := ""
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "-name" && i+1 < len(args):
			i++
			namePattern = args[i]
		case a == "-type" && i+1 < len(args):
			i++
			useType = args[i]
		case a == "-maxdepth" && i+1 < len(args):
			i++ // 忽略深度限制（遍历上限由 VFS Walk 保证）
		case strings.HasPrefix(a, "-"):
			// 忽略其他选项
		default:
			roots = append(roots, a)
		}
	}
	if len(roots) == 0 {
		roots = []string{"."}
	}
	var b strings.Builder
	limit := 0
	for _, r := range roots {
		full := r
		if !strings.HasPrefix(full, "/") {
			full = joinPath(cwd, r)
		}
		userPrefix := r
		e.fs.Walk(full, func(rel string, fi vfs.FileInfo) bool {
			if limit >= 500 { // 结果上限防输出洪泛
				return false
			}
			if useType != "" {
				isDir := fi.IsDir
				if (useType == "f" && isDir) || (useType == "d" && !isDir) {
					return true
				}
			}
			if namePattern != "" && !globMatch(namePattern, fi.Name) {
				return true
			}
			limit++
			// 输出以用户输入路径为前缀的相对路径
			p := userPrefix + "/" + rel
			if !strings.HasPrefix(p, "/") && !strings.HasPrefix(p, "./") {
				p = "./" + p
			}
			b.WriteString(p + "\n")
			return true
		})
	}
	return []byte(b.String())
}

// touchCmd 仿真 touch：创建空文件或更新 mtime
func (e *Executor) touchCmd(cwd string, args []string) []byte {
	var targets []string
	for _, a := range args {
		if strings.HasPrefix(a, "-") {
			continue
		}
		targets = append(targets, a)
	}
	var b strings.Builder
	for _, t := range targets {
		full := absPath(cwd, t)
		if err := e.fs.Touch(full); err != nil {
			fmt.Fprintf(&b, "touch: cannot touch '%s': %s\n", t, err)
		}
	}
	return []byte(b.String())
}

// mkdirCmd 仿真 mkdir/rmdir
func (e *Executor) mkdirCmd(cwd string, args []string) []byte {
	parents := false
	var targets []string
	for _, a := range args {
		switch {
		case a == "-p":
			parents = true
		case strings.HasPrefix(a, "-"):
		default:
			targets = append(targets, a)
		}
	}
	var b strings.Builder
	for _, t := range targets {
		full := absPath(cwd, t)
		if !parents {
			if fi, ok := e.fs.Resolve(path.Dir(full)); !ok || !fi.IsDir {
				fmt.Fprintf(&b, "mkdir: cannot create directory '%s': No such file or directory\n", t)
				continue
			}
		}
		if err := e.fs.Mkdir(full, "drwxr-xr-x", "root", "root"); err != nil {
			fmt.Fprintf(&b, "mkdir: cannot create directory '%s': %s\n", t, err)
		}
	}
	return []byte(b.String())
}

// rmCmd 仿真 rm/rm -r/rm -f
func (e *Executor) rmCmd(cwd string, args []string) []byte {
	recursive, force := false, false
	var targets []string
	for _, a := range args {
		switch {
		case a == "-r" || a == "-R" || a == "-rf" || a == "-fr":
			recursive = true
		case a == "-f":
			force = true
		case strings.HasPrefix(a, "-"):
		default:
			targets = append(targets, a)
		}
	}
	var b strings.Builder
	for _, t := range targets {
		full := absPath(cwd, t)
		var err error
		if recursive {
			err = e.fs.RemoveAll(full)
		} else {
			err = e.fs.Remove(full)
		}
		if err != nil && !force {
			fmt.Fprintf(&b, "rm: cannot remove '%s': %s\n", t, err)
		}
	}
	return []byte(b.String())
}

// mvCmd 仿真 mv：mv src... dst（dst 为目录时移入）
func (e *Executor) mvCmd(cwd string, args []string) []byte {
	if len(args) < 2 {
		return []byte("mv: missing destination file operand\n")
	}
	var srcs []string
	for _, a := range args[:len(args)-1] {
		if strings.HasPrefix(a, "-") {
			continue
		}
		srcs = append(srcs, a)
	}
	dst := args[len(args)-1]
	dstFull := absPath(cwd, dst)
	var b strings.Builder
	for _, s := range srcs {
		srcFull := absPath(cwd, s)
		target := dstFull
		if e.fs.IsDir(dstFull) {
			target = path.Join(dstFull, path.Base(s))
		}
		if err := e.fs.Rename(srcFull, target); err != nil {
			fmt.Fprintf(&b, "mv: cannot move '%s' to '%s': %s\n", s, dst, err)
		}
	}
	return []byte(b.String())
}

// cpCmd 仿真 cp：cp [-r] src... dst
func (e *Executor) cpCmd(cwd string, args []string) []byte {
	recursive := false
	var rest []string
	for _, a := range args {
		switch {
		case a == "-r" || a == "-R" || a == "-rf":
			recursive = true
		case strings.HasPrefix(a, "-"):
		default:
			rest = append(rest, a)
		}
	}
	if len(rest) < 2 {
		return []byte("cp: missing destination file operand\n")
	}
	dst := rest[len(rest)-1]
	dstFull := absPath(cwd, dst)
	var b strings.Builder
	for _, s := range rest[:len(rest)-1] {
		srcFull := absPath(cwd, s)
		if fi, ok := e.fs.Resolve(srcFull); ok && fi.IsDir && !recursive {
			fmt.Fprintf(&b, "cp: -r not specified; omitting directory '%s'\n", s)
			continue
		}
		target := dstFull
		if e.fs.IsDir(dstFull) {
			target = path.Join(dstFull, path.Base(s))
		}
		if err := e.fs.Copy(srcFull, target); err != nil {
			fmt.Fprintf(&b, "cp: cannot stat '%s': %s\n", s, err)
		}
	}
	return []byte(b.String())
}

// chmodCmd 仿真 chmod：数字模式（644/755…）与简化符号模式（+x/-w）
func (e *Executor) chmodCmd(cwd string, args []string) []byte {
	if len(args) < 2 {
		return []byte("chmod: missing operand\n")
	}
	mode := args[0]
	var perm string
	if strings.HasPrefix(mode, "+") || strings.HasPrefix(mode, "-") {
		// 符号模式简化：含 x 设执行位，否则清执行位
		if strings.Contains(mode, "x") {
			perm = "-rwxr-xr-x"
		} else {
			perm = "-rw-r--r--"
		}
	} else {
		perm = octalToPerm(mode)
	}
	var b strings.Builder
	for _, t := range args[1:] {
		if strings.HasPrefix(t, "-") {
			continue
		}
		full := absPath(cwd, t)
		if perm == "" {
			fmt.Fprintf(&b, "chmod: invalid mode: '%s'\n", mode)
			continue
		}
		if err := e.fs.Chmod(full, perm); err != nil {
			fmt.Fprintf(&b, "chmod: cannot access '%s': %s\n", t, err)
		}
	}
	return []byte(b.String())
}

// chownCmd 仿真 chown：chown user[:group] file...
func (e *Executor) chownCmd(cwd string, args []string) []byte {
	if len(args) < 2 {
		return []byte("chown: missing operand\n")
	}
	ug := strings.SplitN(args[0], ":", 2)
	owner, group := ug[0], ""
	if len(ug) > 1 {
		group = ug[1]
	}
	var b strings.Builder
	for _, t := range args[1:] {
		if strings.HasPrefix(t, "-") {
			continue
		}
		full := absPath(cwd, t)
		if err := e.fs.Chown(full, owner, group); err != nil {
			fmt.Fprintf(&b, "chown: cannot access '%s': %s\n", t, err)
		}
	}
	return []byte(b.String())
}

// fileCmd 仿真 file：按内容 magic 判断类型
func (e *Executor) fileCmd(cwd string, args []string) []byte {
	var b strings.Builder
	for _, f := range args {
		if strings.HasPrefix(f, "-") {
			continue
		}
		full := absPath(cwd, f)
		fi, ok := e.fs.Resolve(full)
		if !ok {
			fmt.Fprintf(&b, "%s: cannot open '%s' (No such file or directory)\n", f, f)
			continue
		}
		if fi.IsDir {
			fmt.Fprintf(&b, "%s: directory\n", f)
			continue
		}
		data, err := e.fs.ReadFile(full)
		if err != nil {
			fmt.Fprintf(&b, "%s: data\n", f)
			continue
		}
		fmt.Fprintf(&b, "%s: %s\n", f, detectFileType(full, data))
	}
	return []byte(b.String())
}

// detectFileType 按内容识别文件类型
func detectFileType(name string, data []byte) string {
	if len(data) >= 4 && data[0] == 0x7f && string(data[1:4]) == "ELF" {
		return "ELF 64-bit LSB executable, x86-64"
	}
	if len(data) >= 2 && data[0] == 0x1f && data[1] == 0x8b {
		return "gzip compressed data"
	}
	if len(data) >= 5 && string(data[:5]) == "%PDF-" {
		return "PDF document"
	}
	if strings.HasSuffix(name, ".py") {
		return "Python script, ASCII text executable"
	}
	if strings.HasSuffix(name, ".sh") {
		return "POSIX shell script, ASCII text executable"
	}
	// 是否为二进制（含 NUL）
	for _, c := range data {
		if c == 0 {
			return "data"
		}
	}
	return "ASCII text"
}

// statCmd 仿真 stat：输出文件元数据
func (e *Executor) statCmd(cwd string, args []string) []byte {
	var b strings.Builder
	for _, f := range args {
		if strings.HasPrefix(f, "-") {
			continue
		}
		full := absPath(cwd, f)
		fi, ok := e.fs.Resolve(full)
		if !ok {
			fmt.Fprintf(&b, "stat: cannot stat '%s': No such file or directory\n", f)
			continue
		}
		typ := "regular file"
		if fi.IsDir {
			typ = "directory"
		}
		fsize := fi.Size
		if fi.IsDir {
			fsize = 4096
		}
		ts := fi.Mtime
		if ts.IsZero() {
			ts = time.Now()
		}
		fmt.Fprintf(&b, "  File: %s\n  Size: %d\tBlocks: %d          IO Block: 4096   %s\n"+
			"Device: 800h/2048d\tInode: %d  Links: 1\nAccess: (%s)\tUid: (    0/    root)   Gid: (    0/    root)\n"+
			"Access: %s\nModify: %s\nChange: %s\n Birth: -\n",
			f, fsize, (fsize+1023)/1024*2, typ,
			fnv32(full)%100000+1, fi.Perm,
			ts.Format("2006-01-02 15:04:05.000000000 +0000"),
			ts.Format("2006-01-02 15:04:05.000000000 +0000"),
			ts.Format("2006-01-02 15:04:05.000000000 +0000"))
	}
	return []byte(b.String())
}

// duCmd 仿真 du -sh/-s：统计文件或目录总大小
func (e *Executor) duCmd(cwd string, args []string) []byte {
	human := false
	var targets []string
	for _, a := range args {
		switch {
		case a == "-h" || a == "-sh":
			human = true
		case a == "-s" || a == "-sh" || a == "-k":
		case strings.HasPrefix(a, "-"):
		default:
			targets = append(targets, a)
		}
	}
	if len(targets) == 0 {
		targets = []string{"."}
	}
	var b strings.Builder
	for _, t := range targets {
		full := absPath(cwd, t)
		var total int64
		if fi, ok := e.fs.Resolve(full); ok {
			if fi.IsDir {
				total = 4096
				e.fs.Walk(full, func(_ string, fi vfs.FileInfo) bool {
					if fi.IsDir {
						total += 4096
					} else {
						total += fi.Size
					}
					return true
				})
			} else {
				total = fi.Size
			}
		}
		kb := total / 1024
		if human {
			fmt.Fprintf(&b, "%.1fM\t%s\n", float64(total)/1024/1024, t)
		} else {
			fmt.Fprintf(&b, "%d\t%s\n", kb, t)
		}
	}
	return []byte(b.String())
}

// netstatCmd 动态生成 netstat 输出：LISTEN 行与 ps 进程表联动（sshd 378/nginx 815/mysqld 920），
// 非 -l 模式追加若干动态 ESTABLISHED 连接（本机 IP 与 ifconfig 一致），提升仿真真实度。
func netstatCmd(args []string) []byte {
	joined := strings.Join(args, " ")
	listenOnly := strings.Contains(joined, "-l") || strings.Contains(joined, "--listening")
	if listenOnly {
		return []byte(netstatText)
	}
	var b strings.Builder
	b.WriteString("Active Internet connections (servers and established)\n")
	b.WriteString("Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name\n")
	b.WriteString(netstatBody)
	for i := 0; i < 2+rand.IntN(3); i++ {
		remote := fmt.Sprintf("%d.%d.%d.%d:%d",
			rand.IntN(220)+10, rand.IntN(255), rand.IntN(255), rand.IntN(254)+1, rand.IntN(60000)+1024)
		fmt.Fprintf(&b, "tcp        0      0 10.0.2.15:%d            %-20s ESTABLISHED 378/sshd\n",
			rand.IntN(60000)+40000, remote)
	}
	return []byte(b.String())
}

// netstatText 仿真 netstat -l（PID 与 ps 输出联动：sshd 378 / nginx 815 / mysqld 920）
const netstatText = `Active Internet connections (only servers)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name
` + netstatBody

// netstatBody LISTEN 行主体（netstat 与 netstatCmd 共用）
const netstatBody = `tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      378/sshd
tcp        0      0 0.0.0.0:80              0.0.0.0:*               LISTEN      815/nginx
tcp        0      0 0.0.0.0:443             0.0.0.0:*               LISTEN      815/nginx
tcp        0      0 127.0.0.1:3306          0.0.0.0:*               LISTEN      920/mysqld
tcp6       0      0 :::22                   :::*                    LISTEN      378/sshd
`

// ssText 仿真 ss
const ssText = `Netid State  Recv-Q Send-Q Local Address:Port  Peer Address:Port Process
tcp   LISTEN 0      128         0.0.0.0:22         0.0.0.0:*    users:(("sshd",pid=378,fd=3))
tcp   LISTEN 0      511         0.0.0.0:80         0.0.0.0:*    users:(("nginx",pid=815,fd=6))
tcp   LISTEN 0      128         127.0.0.1:3306     0.0.0.0:*    users:(("mysqld",pid=920,fd=17))
tcp   LISTEN 0      128                [::]:22            [::]:*    users:(("sshd",pid=378,fd=4))
`

// arpText 仿真 arp -a
const arpText = `Address                  HWtype  HWaddress           Flags Mask            Iface
10.0.2.2                 ether   52:54:00:12:35:02   C                     eth0
10.0.2.15                ether   08:00:27:ab:cd:ef   C                     eth0
`

// lastText 仿真 last
const lastText = `root     pts/0        10.0.2.5         Thu Aug 20 08:12   still logged in
root     pts/0        10.0.2.5         Thu Aug 20 07:45 - 08:10  (00:25)
root     pts/1        10.0.2.8         Wed Aug 19 22:30 - 23:05  (00:35)
wtmp begins Mon Jul  1 03:22:00 2024
`

// lastlogText 仿真 lastlog
const lastlogText = `Username         Port     From             Latest
root             pts/0    10.0.2.5         Thu Aug 20 08:12:20 2026
daemon                                     **Never logged in**
bin                                       **Never logged in**
nobody                                    **Never logged in**
`

// wText 仿真 w
func (e *Executor) wText() []byte {
	return []byte(fmt.Sprintf(" %s up 7 days,  1 user,  load average: 0.00, 0.01, 0.05\n"+
		"USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT\n"+
		"root     pts/0    10.0.2.5         08:12    2.00s  0.05s  0.01s -bash\n",
		time.Now().Format("15:04:05")))
}

// absPath 绝对化路径：绝对路径原样返回，相对路径拼接到 cwd
func absPath(cwd, p string) string {
	if strings.HasPrefix(p, "/") {
		return p
	}
	return joinPath(cwd, p)
}

// fnv32 字符串 FNV-1a 哈希（用于 stat 的确定性 inode 编号）
func fnv32(s string) uint32 {
	h := fnv.New32a()
	h.Write([]byte(s))
	return h.Sum32()
}

// octalToPerm 将 3 位八进制模式转为 9 字符权限串（如 "755"→"rwxr-xr-x"）；非法返回 ""
func octalToPerm(mode string) string {
	if len(mode) > 3 {
		mode = mode[len(mode)-3:]
	}
	n := 0
	for _, c := range mode {
		if c < '0' || c > '7' {
			return ""
		}
		n = n*8 + int(c-'0')
	}
	ds := [3]int{n / 64 % 8, n / 8 % 8, n % 8}
	var b []byte
	for i := 0; i < 3; i++ {
		for j := 0; j < 3; j++ {
			mask := 4 >> j // 读/写/执行
			if ds[i]&mask != 0 {
				b = append(b, []byte("rwx")[j])
			} else {
				b = append(b, '-')
			}
		}
	}
	return string(b)
}

// globMatch 简单通配符匹配（支持 * ? []），用于 find -name
func globMatch(pattern, s string) bool {
	pi, si := 0, 0
	for pi < len(pattern) {
		switch pattern[pi] {
		case '*':
			if pi == len(pattern)-1 {
				return true
			}
			for si <= len(s) {
				if globMatch(pattern[pi+1:], s[si:]) {
					return true
				}
				si++
			}
			return false
		case '?':
			if si >= len(s) {
				return false
			}
			pi++
			si++
		case '[':
			end := pi + 1
			for end < len(pattern) && pattern[end] != ']' {
				end++
			}
			if end < len(pattern) && si < len(s) {
				if strings.ContainsRune(pattern[pi+1:end], rune(s[si])) {
					pi = end + 1
					si++
					continue
				}
			}
			return false
		default:
			if si >= len(s) || pattern[pi] != s[si] {
				return false
			}
			pi++
			si++
		}
	}
	return si == len(s)
}

func (e *Executor) ps(args []string) []byte {
	if len(args) > 0 && (args[0] == "-ef" || args[0] == "-aux") {
		return []byte(`UID          PID    PPID  C STIME TTY          TIME CMD
root           1       0  0 00:00 ?        00:00:02 /sbin/init
root         378       1  0 00:00 ?        00:00:00 /usr/sbin/sshd -D
root         402     378  0 00:00 ?        00:00:00 sshd: root@pts/0
root         403     402  0 00:00 pts/0    00:00:00 -bash
root         410     403  0 00:00 pts/0    00:00:00 ps -ef
`)
	}
	return []byte(`  PID TTY          TIME CMD
  402 pts/0    00:00:00 bash
  410 pts/0    00:00:00 ps
`)
}

// preview 截取输出前 200 字节作为摘要
func preview(b []byte) string {
	const maxPreview = 200
	if len(b) > maxPreview {
		return string(b[:maxPreview]) + "...(truncated)"
	}
	return string(b)
}

// --- 解析辅助 ---

type logicToken struct {
	op  string
	cmd string
}

// splitLogical 按 && 和 || 拆分（引号感知）
func splitLogical(s string) []logicToken {
	var tokens []logicToken
	last := 0
	op := ""
	var quote byte
	for i := 0; i+1 < len(s); {
		c := s[i]
		if quote != 0 {
			if c == quote {
				quote = 0
			}
			i++
			continue
		}
		switch c {
		case '\'', '"':
			quote = c
			i++
			continue
		}
		if (s[i] == '&' && s[i+1] == '&') || (s[i] == '|' && s[i+1] == '|') {
			tokens = append(tokens, logicToken{op: op, cmd: s[last:i]})
			op = s[i : i+2]
			last = i + 2
			i += 2
			continue
		}
		i++
	}
	tokens = append(tokens, logicToken{op: op, cmd: s[last:]})
	return tokens
}

// splitTopLevel 按分隔符拆分（忽略引号内的分隔符）
func splitTopLevel(s string, sep byte) []string {
	var parts []string
	start := 0
	var quote byte
	for i := 0; i < len(s); i++ {
		c := s[i]
		if quote != 0 {
			if c == quote {
				quote = 0
			}
			continue
		}
		switch c {
		case '\'', '"':
			quote = c
		case sep:
			parts = append(parts, s[start:i])
			start = i + 1
		}
	}
	parts = append(parts, s[start:])
	return parts
}

// tokenize 引号感知的命令分词
func tokenize(s string) []string {
	var tokens []string
	var cur strings.Builder
	var quote byte
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case quote != 0:
			if c == quote {
				quote = 0
			} else {
				cur.WriteByte(c)
			}
		case c == '\'' || c == '"':
			quote = c
		case c == ' ' || c == '\t':
			if cur.Len() > 0 {
				tokens = append(tokens, cur.String())
				cur.Reset()
			}
		case c == '\\' && i+1 < len(s):
			i++
			cur.WriteByte(s[i])
		default:
			cur.WriteByte(c)
		}
	}
	if cur.Len() > 0 {
		tokens = append(tokens, cur.String())
	}
	return tokens
}

func joinPath(cwd, p string) string {
	if p == "." {
		return cwd
	}
	if strings.HasPrefix(p, "./") {
		p = p[2:]
	}
	if p == "/" {
		return "/"
	}
	return strings.TrimSuffix(cwd, "/") + "/" + p
}
