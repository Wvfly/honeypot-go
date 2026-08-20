package shell

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"io/fs"
	"sort"
	"strings"

	"mvdan.cc/sh/v3/expand"
	"mvdan.cc/sh/v3/syntax"

	"honeypot-go/internal/event"
)

// M2: 基于 mvdan.cc/sh 的完整 shell 语法解析。
// 支持: 引号/转义、变量展开($HOME)、通配符(ls /etc/*.conf)、命令替换($()/反引号)、
//       管道(|)、逻辑操作符(&&/||)、分号(;)、重定向(>、>>)、后台(&)、否定(!)。

// runAST 解析并执行整段命令串（优先路径），失败时返回 false 由调用方 fallback。
func (e *Executor) runAST(cwd, raw string) (string, int, []byte, bool) {
	f, err := syntax.NewParser().Parse(strings.NewReader(raw), "")
	if err != nil {
		return cwd, 0, nil, false
	}
	var out []byte
	code := 0
	for _, stmt := range f.Stmts {
		var c int
		cwd, c, out = e.runStmt(cwd, stmt, out)
		code = c
	}
	return cwd, code, out, true
}

// runStmt 执行一条语句（处理 !、后台、子 shell、&&/||/|）
func (e *Executor) runStmt(cwd string, stmt *syntax.Stmt, out []byte) (string, int, []byte) {
	if stmt.Background {
		// 后台执行 &：简化——同步执行，输出照常合并
		s := *stmt
		s.Background = false
		return e.runStmt(cwd, &s, out)
	}
	var code int
	switch cmd := stmt.Cmd.(type) {
	case *syntax.BinaryCmd:
		switch cmd.Op {
		case syntax.Pipe:
			// 管道链：展开为语句序列后按过滤语义执行
			cwd, code, out = e.runPipeChain(cwd, pipeCmds(stmt), out)
		default: // && / ||
			var xc int
			cwd, xc, out = e.runStmt(cwd, cmd.X, out)
			runY := (cmd.Op == syntax.AndStmt && xc == 0) || (cmd.Op == syntax.OrStmt && xc != 0)
			if runY {
				var yc int
				cwd, yc, out = e.runStmt(cwd, cmd.Y, out)
				if cmd.Op == syntax.OrStmt && yc == 0 {
					xc = 0
				} else {
					xc = yc
				}
			}
			code = xc
		}

	case *syntax.CallExpr:
		cwd, code, out = e.runCall(cwd, cmd, stmt.Redirs, out)

	case *syntax.Subshell:
		// 子 shell (...) 或 $() 内联：同步执行合并输出
		for _, s := range cmd.Stmts {
			cwd, code, out = e.runStmt(cwd, s, out)
		}

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
func (e *Executor) runPipeChain(cwd string, stmts []*syntax.Stmt, out []byte) (string, int, []byte) {
	var (
		code int
		buf  []byte
	)
	for i, s := range stmts {
		call, ok := s.Cmd.(*syntax.CallExpr)
		if !ok {
			continue
		}
		args, err := e.expandArgs(cwd, call)
		if err != nil || len(args) == 0 {
			continue
		}
		bin := stripPath(args[0])
		if i > 0 && isFilter(bin) {
			// 下游过滤命令：处理上游输出
			buf = e.runFilter(bin, args[1:], buf)
			continue
		}
		// 首段或非过滤段：正常执行
		cwd, code, buf = e.runCall(cwd, call, s.Redirs, buf)
	}
	out = append(out, buf...)
	return cwd, code, out
}

// runCall 展开参数并执行单条命令；处理重定向(>/>>)
func (e *Executor) runCall(cwd string, call *syntax.CallExpr, redirs []*syntax.Redirect, out []byte) (string, int, []byte) {
	args, err := e.expandArgs(cwd, call)
	if err != nil || len(args) == 0 {
		return cwd, 0, out
	}
	var code int
	prefix := len(out)
	cwd, code, out = e.execOne(cwd, args, out)

	// 重定向：把本次输出写入文件，终端不再显示
	for _, r := range redirs {
		target, terr := e.expandWord(cwd, r.Word)
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
		e.publishFileWritten(path, added)
	}
	return cwd, code, out
}

// expandArgs 字段展开一条命令的全部参数（引号/变量/通配符/命令替换）
func (e *Executor) expandArgs(cwd string, call *syntax.CallExpr) ([]string, error) {
	return expand.Fields(e.expandConfig(cwd), call.Args...)
}

// expandConfig 构造展开配置：环境变量、命令替换 $()/“、通配符（走 VFS）
func (e *Executor) expandConfig(cwd string) *expand.Config {
	return &expand.Config{
		Env: expand.FuncEnviron(func(name string) string {
			switch name {
			case "HOME", "PWD":
				return cwd
			case "USER":
				return "root"
			case "SHELL":
				return "/bin/bash"
			case "HOSTNAME":
				return e.hostname
			}
			return "" // 空串视为未设置
		}),
		CmdSubst: func(w io.Writer, cs *syntax.CmdSubst) error {
			var out []byte
			for _, s := range cs.Stmts {
				var c int
				_, c, out = e.runStmt(cwd, s, out)
				_ = c
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
func (e *Executor) expandWord(cwd string, w *syntax.Word) (string, error) {
	if w == nil {
		return "", nil
	}
	parts, err := expand.Fields(e.expandConfig(cwd), w)
	if err != nil {
		return "", err
	}
	if len(parts) == 0 {
		return "", nil
	}
	return parts[0], nil
}

func (e *Executor) publishFileWritten(path string, data []byte) {
	e.bus.Publish(event.New(event.TypeFileWritten, map[string]any{
		"session_id": e.sessionID(),
		"path":       path,
		"size":       len(data),
		"sha256":     sha256sum(data),
	}))
}

// isFilter 是否为管道过滤命令
func isFilter(bin string) bool {
	switch bin {
	case "grep", "egrep", "fgrep", "head", "tail", "wc", "sort", "uniq", "cat":
		return true
	}
	return false
}

// runFilter 对输入应用过滤命令
func (e *Executor) runFilter(bin string, args []string, input []byte) []byte {
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
	}
	return input
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
	return e.runFilter(bin, args, data)
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
