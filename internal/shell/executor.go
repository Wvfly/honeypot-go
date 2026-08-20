package shell

import (
	"fmt"
	"log/slog"
	"strings"
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
}

// execCtx 单次 Execute 的执行上下文：承载会话 ID 与命令替换/子 shell 嵌套深度。
// 每次 Execute 独立创建，仅在同一 goroutine 内同步使用，无跨会话共享。
type execCtx struct {
	sessionID string
	depth     int
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
	return &Executor{fs: fs, bus: bus, hostname: hostname, logger: logger, vnet: vnet.New(bus, logger)}
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

// Execute 执行一段命令串（可含 ; && || | $()），返回最终 exit code 与合并输出。
// 返回执行后的新 cwd（支持 cd 状态变更）。
func (e *Executor) Execute(sessionID, cwd, raw string) (string, Result) {
	ctx := &execCtx{sessionID: sessionID}

	start := time.Now()
	var (
		newCwd string
		code   int
		output []byte
		ok     bool
	)
	newCwd, code, output, ok = e.runAST(ctx, cwd, raw)
	if !ok {
		// AST 解析失败（非常规语法），fallback 到旧的轻量解析
		newCwd, code, output = e.runSequence(ctx, cwd, raw)
	}
	output = limitOutput(output)
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
		line := strings.Join(rest, " ") + "\n"
		return cwd, 0, append(out, []byte(line)...)
	case "hostname":
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
		return cwd, 0, append(out, []byte("    1  ls -la\n    2  whoami\n    3  cat /etc/passwd\n")...)
	case "true":
		return cwd, 0, out
	case "false":
		return cwd, 1, out
	case "exit", "logout":
		return cwd, 0, out
	case "grep", "egrep", "fgrep", "head", "tail", "wc", "sort", "uniq":
		return cwd, 0, append(out, e.filterCmd(cwd, bin, rest)...)
	default:
		out = append(out, []byte("bash: "+args[0]+": command not found\n")...)
		return cwd, 127, out
	}
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
	path := cwd
	showAll := false
	long := false
	for _, a := range args {
		switch {
		case a == "-a" || a == "-la" || a == "-al":
			showAll, long = true, true
		case a == "-l":
			long = true
		case strings.HasPrefix(a, "-"):
			// 忽略其他选项
		default:
			path = a
		}
	}
	if !strings.HasPrefix(path, "/") {
		path = joinPath(cwd, path)
	}
	infos, err := e.fs.List(path)
	if err != nil {
		return []byte("ls: cannot access '" + args[len(args)-1] + "': No such file or directory\n")
	}
	if !long {
		var names []string
		for _, f := range infos {
			if strings.HasPrefix(f.Name, ".") && !showAll {
				continue
			}
			names = append(names, f.Name)
		}
		return []byte(strings.Join(names, "  ") + "\n")
	}
	var b strings.Builder
	for _, f := range infos {
		if strings.HasPrefix(f.Name, ".") && !showAll {
			continue
		}
		size := f.Size
		if f.IsDir {
			size = 4096
		}
		fmt.Fprintf(&b, "%s %s %s %8d %s %s\n",
			f.Perm, f.Owner, f.Group, size,
			"Jan 01 12:00", f.Name)
	}
	return []byte(b.String())
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
	const max = 200
	if len(b) > max {
		return string(b[:max]) + "...(truncated)"
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
