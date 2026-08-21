package shell

import (
	"crypto/md5"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"hash"
	"io"
	"io/fs"
	"sort"
	"strconv"
	"strings"

	"mvdan.cc/sh/v3/expand"
	"mvdan.cc/sh/v3/syntax"

	"honeypot-go/internal/event"
)

// M2: 基于 mvdan.cc/sh 的完整 shell 语法解析。
// 支持: 引号/转义、变量展开($HOME)、通配符(ls /etc/*.conf)、命令替换($()/反引号)、
//       管道(|)、逻辑操作符(&&/||)、分号(;)、重定向(>、>>)、后台(&)、否定(!)。

// runAST 解析并执行整段命令串（优先路径），失败时返回 false 由调用方 fallback。
func (e *Executor) runAST(ctx *execCtx, cwd, raw string) (string, int, []byte, bool) {
	f, err := syntax.NewParser().Parse(strings.NewReader(raw), "")
	if err != nil {
		return cwd, 0, nil, false
	}
	var out []byte
	code := 0
	for _, stmt := range f.Stmts {
		var c int
		cwd, c, out = e.runStmt(ctx, cwd, stmt, out)
		out = capOut(out) // 中间软上限：防多语句命令串 out 无限累积放大内存
		code = c
	}
	return cwd, code, out, true
}

// runStmt 执行一条语句（处理 !、后台、子 shell、&&/||/|）
func (e *Executor) runStmt(ctx *execCtx, cwd string, stmt *syntax.Stmt, out []byte) (string, int, []byte) {
	if stmt.Background {
		// 后台执行 &：简化——同步执行，输出照常合并
		s := *stmt
		s.Background = false
		return e.runStmt(ctx, cwd, &s, out)
	}
	var code int
	switch cmd := stmt.Cmd.(type) {
	case *syntax.BinaryCmd:
		switch cmd.Op {
		case syntax.Pipe:
			// 管道链：展开为语句序列后按过滤语义执行
			cwd, code, out = e.runPipeChain(ctx, cwd, pipeCmds(stmt), out)
		default: // && / ||
			var xc int
			cwd, xc, out = e.runStmt(ctx, cwd, cmd.X, out)
			runY := (cmd.Op == syntax.AndStmt && xc == 0) || (cmd.Op == syntax.OrStmt && xc != 0)
			if runY {
				var yc int
				cwd, yc, out = e.runStmt(ctx, cwd, cmd.Y, out)
				if cmd.Op == syntax.OrStmt && yc == 0 {
					xc = 0
				} else {
					xc = yc
				}
			}
			code = xc
		}

	case *syntax.CallExpr:
		cwd, code, out = e.runCall(ctx, cwd, cmd, stmt.Redirs, out)

	case *syntax.Subshell:
		// 子 shell (...) 或 $() 内联：同步执行合并输出（限制嵌套深度）
		if ctx.depth >= maxCmdSubstDepth {
			return cwd, 1, out
		}
		ctx.depth++
		for _, s := range cmd.Stmts {
			cwd, code, out = e.runStmt(ctx, cwd, s, out)
		}
		ctx.depth--

	default:
		// 其他语句类型（if/for/赋值等）：简单忽略
		code = 0
	}
	if stmt.Negated {
		code = flipCode(code)
	}
	return cwd, code, out
}

// pipeCmds 把嵌套的管道 BinaryCmd 展开为语句序列（a | b | c → [a, b, c]）
func pipeCmds(stmt *syntax.Stmt) []*syntax.Stmt {
	if b, ok := stmt.Cmd.(*syntax.BinaryCmd); ok && b.Op == syntax.Pipe {
		return append(pipeCmds(b.X), pipeCmds(b.Y)...)
	}
	return []*syntax.Stmt{stmt}
}

// runPipeChain 执行管道链：非过滤命令输出作为下游过滤命令输入
func (e *Executor) runPipeChain(ctx *execCtx, cwd string, stmts []*syntax.Stmt, out []byte) (string, int, []byte) {
	var (
		code int
		buf  []byte
	)
	for i, s := range stmts {
		call, ok := s.Cmd.(*syntax.CallExpr)
		if !ok {
			continue
		}
		args, err := e.expandArgs(ctx, cwd, call)
		if err != nil || len(args) == 0 {
			continue
		}
		bin := stripPath(args[0])
		if i > 0 && isFilter(bin) {
			// 下游过滤命令：处理上游输出
			buf = e.runFilter(cwd, bin, args[1:], buf)
			continue
		}
		// 首段或非过滤段：正常执行
		cwd, code, buf = e.runCall(ctx, cwd, call, s.Redirs, buf)
	}
	out = append(out, buf...)
	out = capOut(out) // 中间软上限：防管道链输出累积放大内存
	return cwd, code, out
}

// runCall 展开参数并执行单条命令；处理重定向(>/>>)
func (e *Executor) runCall(ctx *execCtx, cwd string, call *syntax.CallExpr, redirs []*syntax.Redirect, out []byte) (string, int, []byte) {
	args, err := e.expandArgs(ctx, cwd, call)
	if err != nil || len(args) == 0 {
		return cwd, 0, out
	}
	var code int
	prefix := len(out)
	cwd, code, out = e.execOne(ctx, cwd, args, out)

	// 重定向：把本次输出写入文件，终端不再显示
	for _, r := range redirs {
		target, terr := e.expandWord(ctx, cwd, r.Word)
		if terr != nil || target == "" {
			continue
		}
		path := target
		if !strings.HasPrefix(path, "/") {
			path = joinPath(cwd, path)
		}
		added := out[prefix:]
		out = out[:prefix]
		switch r.Op {
		case syntax.AppOut: // >>
			_ = e.fs.AppendFile(path, added)
		default: // > 及其他输出重定向
			_ = e.fs.WriteFile(path, added)
		}
		e.publishFileWritten(ctx, path, added)
	}
	return cwd, code, out
}

// expandArgs 字段展开一条命令的全部参数（引号/变量/通配符/命令替换）
func (e *Executor) expandArgs(ctx *execCtx, cwd string, call *syntax.CallExpr) ([]string, error) {
	return expand.Fields(e.expandConfig(ctx, cwd), call.Args...)
}

// expandConfig 构造展开配置：环境变量、命令替换 $()/“、通配符（走 VFS）
func (e *Executor) expandConfig(ctx *execCtx, cwd string) *expand.Config {
	return &expand.Config{
		Env: expand.FuncEnviron(func(name string) string {
			switch name {
			case "HOME": // 仿真 root 登录：家目录固定 /root，而非当前目录
				return "/root"
			case "PWD":
				return cwd
			case "USER", "LOGNAME":
				return "root"
			case "SHELL":
				return "/bin/bash"
			case "HOSTNAME":
				return e.hostname
			case "PATH":
				return "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
			case "LANG":
				return "en_US.UTF-8"
			case "TERM":
				return "xterm-256color"
			case "?": // 上一条命令退出码
				return strconv.Itoa(ctx.lastCode)
			case "$": // shell PID
				return ctx.pid
			case "#": // 位置参数个数
				return "0"
			}
			return "" // 空串视为未设置
		}),
		CmdSubst: func(w io.Writer, cs *syntax.CmdSubst) error {
			// 防深嵌套命令替换耗尽栈/CPU
			if ctx.depth >= maxCmdSubstDepth {
				return fmt.Errorf("command substitution nesting too deep")
			}
			ctx.depth++
			defer func() { ctx.depth-- }()
			var out []byte
			for _, s := range cs.Stmts {
				var c int
				_, c, out = e.runStmt(ctx, cwd, s, out)
				_ = c
				// 命令替换输出同样受限，防止内存放大
				if len(out) >= maxOutputSize {
					out = out[:maxOutputSize]
					break
				}
			}
			_, err := w.Write(out)
			return err
		},
		ReadDir2: func(path string) ([]fs.DirEntry, error) {
			return e.fs.ReadDir2(path)
		},
	}
}

// expandWord 展开单个 word 为重定向目标
func (e *Executor) expandWord(ctx *execCtx, cwd string, w *syntax.Word) (string, error) {
	if w == nil {
		return "", nil
	}
	parts, err := expand.Fields(e.expandConfig(ctx, cwd), w)
	if err != nil {
		return "", err
	}
	if len(parts) == 0 {
		return "", nil
	}
	return parts[0], nil
}

func (e *Executor) publishFileWritten(ctx *execCtx, path string, data []byte) {
	e.bus.Publish(event.New(event.TypeFileWritten, map[string]any{
		"session_id": ctx.sessionID,
		"path":       path,
		"size":       len(data),
		"sha256":     sha256sum(data),
	}))
}

// isFilter 是否为管道过滤命令
func isFilter(bin string) bool {
	switch bin {
	case "grep", "egrep", "fgrep", "head", "tail", "wc", "sort", "uniq", "cat",
		"awk", "sed", "cut", "tr", "base64", "strings", "tee", "xargs", "sha256sum", "md5sum":
		return true
	}
	return false
}

// runFilter 对输入应用过滤命令；cwd 供 tee 等写文件命令使用
func (e *Executor) runFilter(cwd, bin string, args []string, input []byte) []byte {
	lines := strings.Split(strings.TrimRight(string(input), "\n"), "\n")
	if len(input) == 0 || (len(lines) == 1 && lines[0] == "") {
		lines = nil
	}
	switch bin {
	case "grep", "egrep", "fgrep":
		pat := ""
		invert := false
		count := false
		for _, a := range args {
			if a == "-v" {
				invert = true
			} else if a == "-c" {
				count = true
			} else if !strings.HasPrefix(a, "-") && pat == "" {
				pat = a
			}
		}
		var matched []string
		for _, l := range lines {
			hit := strings.Contains(l, pat)
			if invert {
				hit = !hit
			}
			if hit {
				matched = append(matched, l)
			}
		}
		if count {
			return []byte(fmt.Sprintf("%d\n", len(matched)))
		}
		return []byte(strings.Join(matched, "\n") + maybeNL(matched))

	case "head":
		n := 10
		for i := 0; i < len(args); i++ {
			a := args[i]
			if a == "-n" && i+1 < len(args) {
				n = atoi(args[i+1])
				i++
			} else if strings.HasPrefix(a, "-n") && len(a) > 2 {
				n = atoi(a[2:])
			} else if strings.HasPrefix(a, "-") && len(a) > 1 && a[1] >= '0' && a[1] <= '9' {
				n = atoi(a[1:])
			}
		}
		if n > len(lines) {
			n = len(lines)
		}
		if n < 0 {
			n = 0
		}
		return []byte(strings.Join(lines[:n], "\n") + maybeNL(lines[:n]))

	case "tail":
		n := 10
		for i := 0; i < len(args); i++ {
			a := args[i]
			if a == "-n" && i+1 < len(args) {
				n = atoi(args[i+1])
				i++
			} else if strings.HasPrefix(a, "-n") && len(a) > 2 {
				n = atoi(a[2:])
			} else if strings.HasPrefix(a, "-") && len(a) > 1 && a[1] >= '0' && a[1] <= '9' {
				n = atoi(a[1:])
			}
		}
		if n > len(lines) {
			n = len(lines)
		}
		if n < 0 {
			n = 0
		}
		start := len(lines) - n
		if start < 0 {
			start = 0
		}
		return []byte(strings.Join(lines[start:], "\n") + maybeNL(lines[start:]))

	case "wc":
		words, chars, cnt := 0, 0, len(lines)
		for _, l := range lines {
			words += len(strings.Fields(l))
			chars += len(l) + 1
		}
		if contains(args, "-l") {
			return []byte(fmt.Sprintf("%d\n", cnt))
		}
		if contains(args, "-w") {
			return []byte(fmt.Sprintf("%d\n", words))
		}
		if contains(args, "-c") {
			return []byte(fmt.Sprintf("%d\n", chars))
		}
		return []byte(fmt.Sprintf("%d %d %d\n", cnt, words, chars))

	case "sort":
		sorted := append([]string(nil), lines...)
		sortStrings(sorted)
		return []byte(strings.Join(sorted, "\n") + maybeNL(sorted))

	case "uniq":
		var u []string
		for _, l := range lines {
			if len(u) == 0 || u[len(u)-1] != l {
				u = append(u, l)
			}
		}
		return []byte(strings.Join(u, "\n") + maybeNL(u))

	case "cat":
		// cat 无参数作为过滤器：透传
		if len(args) == 0 {
			return input
		}

	case "cut":
		delim := "\t"
		var fields []int
		for i := 0; i < len(args); i++ {
			a := args[i]
			if a == "-d" && i+1 < len(args) {
				i++
				delim = args[i]
			} else if a == "-f" && i+1 < len(args) {
				i++
				for _, fs := range strings.Split(args[i], ",") {
					if f := atoi(fs); f > 0 {
						fields = append(fields, f)
					}
				}
			}
		}
		var cut []string
		for _, l := range lines {
			parts := strings.Split(l, delim)
			var picked []string
			for _, f := range fields {
				if f-1 < len(parts) {
					picked = append(picked, parts[f-1])
				}
			}
			if len(picked) == 0 {
				continue
			}
			cut = append(cut, strings.Join(picked, delim))
		}
		return []byte(strings.Join(cut, "\n") + maybeNL(cut))

	case "tr":
		set1, set2 := "", ""
		deleteMode := false
		for _, a := range args {
			switch {
			case a == "-d" || a == "--delete":
				deleteMode = true
			case strings.HasPrefix(a, "-"):
			case set1 == "":
				set1 = a
			case set2 == "":
				set2 = a
			}
		}
		var trOut []string
		for _, l := range lines {
			var b strings.Builder
			for _, r := range l {
				if deleteMode {
					if !strings.ContainsRune(set1, r) {
						b.WriteRune(r)
					}
					continue
				}
				if i := strings.IndexRune(set1, r); i >= 0 && i < len(set2) {
					b.WriteRune(rune(set2[i]))
				} else {
					b.WriteRune(r)
				}
			}
			trOut = append(trOut, b.String())
		}
		return []byte(strings.Join(trOut, "\n") + maybeNL(trOut))

	case "sed":
		for _, a := range args {
			if strings.HasPrefix(a, "s/") {
				rest := a[2:]
				parts := strings.SplitN(rest, "/", 3)
				if len(parts) >= 2 {
					old, rep := parts[0], parts[1]
					global := len(parts) > 2 && parts[2] == "g"
					var sedOut []string
					for _, l := range lines {
						if global {
							sedOut = append(sedOut, strings.ReplaceAll(l, old, rep))
						} else {
							sedOut = append(sedOut, strings.Replace(l, old, rep, 1))
						}
					}
					return []byte(strings.Join(sedOut, "\n") + maybeNL(sedOut))
				}
			}
		}
		return input

	case "awk":
		delim := " "
		program := ""
		for i := 0; i < len(args); i++ {
			a := args[i]
			switch {
			case a == "-F" && i+1 < len(args):
				i++
				delim = args[i]
			case strings.HasPrefix(a, "-F") && len(a) > 2:
				delim = a[2:]
			case strings.HasPrefix(a, "{"):
				program = a
			}
		}
		var awkOut []string
		for _, l := range lines {
			parts := strings.Split(l, delim)
			if strings.Contains(program, "$NF") {
				if len(parts) > 0 {
					awkOut = append(awkOut, parts[len(parts)-1])
				}
				continue
			}
			var picked []string
			for _, f := range strings.Fields(strings.Trim(program, "{} ")) {
				if strings.HasPrefix(f, "$") && len(f) > 1 {
					idx := atoi(f[1:])
					if idx > 0 && idx <= len(parts) {
						picked = append(picked, parts[idx-1])
					}
				}
			}
			if len(picked) > 0 {
				awkOut = append(awkOut, strings.Join(picked, " "))
			}
		}
		return []byte(strings.Join(awkOut, "\n") + maybeNL(awkOut))

	case "base64":
		decode := false
		for _, a := range args {
			if a == "-d" || a == "--decode" || a == "-D" {
				decode = true
			}
		}
		data := strings.TrimRight(string(input), "\n")
		if decode {
			raw, err := base64.StdEncoding.DecodeString(data)
			if err != nil {
				return input
			}
			return raw
		}
		return []byte(base64.StdEncoding.EncodeToString(input) + "\n")

	case "sha256sum", "md5sum":
		h := hashForBin(bin)
		h.Write(input)
		return []byte(fmt.Sprintf("%x  -\n", h.Sum(nil)))

	case "strings":
		// 简化：仅保留可打印 ASCII 行（长度 >= 4）
		var strOut []string
		for _, l := range lines {
			if l == "" {
				continue
			}
			clean := printableOnly(l)
			if len(clean) >= 4 {
				strOut = append(strOut, clean)
			}
		}
		return []byte(strings.Join(strOut, "\n") + maybeNL(strOut))

	case "tee":
		for _, a := range args {
			if strings.HasPrefix(a, "-") {
				continue
			}
			full := a
			if !strings.HasPrefix(full, "/") {
				full = joinPath(cwd, full)
			}
			_ = e.fs.WriteFile(full, input)
		}
		return input

	case "xargs":
		// 简化：无参数 xargs 直接回显输入（echo 语义）
		return input
	}
	return input
}

// hashForBin 返回 sha256sum/md5sum 对应的 hash.Hash
func hashForBin(bin string) hash.Hash {
	if bin == "md5sum" {
		return md5.New()
	}
	return sha256.New()
}

// printableOnly 保留可打印 ASCII 与换行，用于 strings 命令仿真
func printableOnly(s string) string {
	var b strings.Builder
	for _, r := range s {
		if r >= 0x20 && r <= 0x7e {
			b.WriteRune(r)
		} else {
			b.WriteByte(' ')
		}
	}
	return strings.TrimSpace(b.String())
}

// stripPath 去掉命令的路径前缀（/bin/ls → ls）
func stripPath(bin string) string {
	if i := strings.LastIndex(bin, "/"); i >= 0 {
		return bin[i+1:]
	}
	return bin
}

// filterCmd 单命令执行过滤命令（grep/head/tail/wc/sort/uniq + 文件参数），
// 无 stdin 时读取 VFS 文件作为输入。
func (e *Executor) filterCmd(cwd, bin string, args []string) []byte {
	var paths []string
	for _, a := range args {
		if strings.HasPrefix(a, "-") {
			continue
		}
		paths = append(paths, a)
	}
	var data []byte
	for _, p := range paths {
		if !strings.HasPrefix(p, "/") {
			p = joinPath(cwd, p)
		}
		if b, err := e.fs.ReadFile(p); err == nil {
			data = append(data, b...)
		}
	}
	return e.runFilter(cwd, bin, args, data)
}

// --- 辅助函数 ---

func flipCode(c int) int {
	if c == 0 {
		return 1
	}
	return 0
}

func maybeNL(lines []string) string {
	if len(lines) > 0 && lines[len(lines)-1] != "" {
		return "\n"
	}
	return ""
}

func atoi(s string) int {
	n := 0
	for _, c := range s {
		if c < '0' || c > '9' {
			return 0
		}
		n = n*10 + int(c-'0')
	}
	return n
}

func contains(ss []string, want string) bool {
	for _, s := range ss {
		if s == want {
			return true
		}
	}
	return false
}

func sortStrings(ss []string) {
	sort.Strings(ss)
}

func sha256sum(b []byte) string {
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}
