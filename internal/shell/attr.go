package shell

import (
	"fmt"
	"path"
	"strings"

	"honeypot-go/internal/vfs"
)

// 仿真 e2fsprogs 的 chattr / lsattr（ext4，属性位与输出格式对齐 Ubuntu 22.04 的 1.46.5）。
// 属性存放在 VFS 节点上：+i（不可变）/+a（只可追加）由 VFS 强制执行，
// 之后对该文件的写入、删除、重命名、chmod 会报 "Operation not permitted"，root 也不例外，
// 与真实系统一致——攻击者常用 chattr +i 锁住自己的 authorized_keys / 定时任务，再用 chattr -i 解锁别人的。

const (
	chattrUsage = "Usage: chattr [-pRVf] [-+=aAcCdDeijPsStTuFx] [-v version] files...\n"
	lsattrUsage = "Usage: lsattr [-RVadlpv] [files...]\n"

	// 可用于 chattr 模式的属性字母
	chattrModeLetters = "aAcCdDeFijmPsStTux"

	// 单次输出行数上限：防 lsattr -R / 之类的命令产生过量输出
	maxAttrLines = 2000
	// chattr -R 单次处理节点数上限
	maxAttrTargets = 5000
)

// noAttrPath 这些位置在真实系统上不是 ext4（procfs/sysfs/devtmpfs/tmpfs），
// lsattr/chattr 会报 "Inappropriate ioctl for device"。
func noAttrPath(full string) bool {
	for _, pre := range []string{"/proc", "/sys", "/dev", "/run"} {
		if full == pre || strings.HasPrefix(full, pre+"/") {
			return true
		}
	}
	return false
}

// lsattrCmd 仿真 lsattr [-RVadlpv] [files...]
func (e *Executor) lsattrCmd(cwd string, args []string) ([]byte, int) {
	var recursive, all, dirsOnly, long bool
	var files []string
	var b strings.Builder
	code := 0

	endOpts := false
	for _, a := range args {
		if !endOpts && a == "--" {
			endOpts = true
			continue
		}
		if !endOpts && len(a) > 1 && a[0] == '-' {
			for _, c := range a[1:] {
				switch c {
				case 'R':
					recursive = true
				case 'a':
					all = true
				case 'd':
					dirsOnly = true
				case 'l':
					long = true
				case 'V':
					b.WriteString("lsattr 1.46.5 (30-Dec-2021)\n")
				case 'p', 'v': // 项目号 / 文件版本号：本仿真不区分，忽略
				default:
					fmt.Fprintf(&b, "lsattr: invalid option -- '%c'\n%s", c, lsattrUsage)
					return []byte(b.String()), 1
				}
			}
			continue
		}
		files = append(files, a)
	}
	if len(files) == 0 {
		files = []string{"."}
	}

	lines := 0
	// show 输出一个条目；display 是展示给用户的路径（保持用户给出的写法），full 是 VFS 绝对路径
	show := func(display, full string) {
		if lines >= maxAttrLines {
			return
		}
		lines++
		if noAttrPath(full) {
			fmt.Fprintf(&b, "lsattr: Inappropriate ioctl for device While reading flags on %s\n", display)
			code = 1
			return
		}
		flags, ok := e.fs.Attrs(full)
		if !ok {
			return
		}
		if long {
			names := vfs.AttrNames(flags)
			s := "---"
			if len(names) > 0 {
				s = strings.Join(names, ", ")
			}
			fmt.Fprintf(&b, "%-28s %s\n", display, s)
			return
		}
		fmt.Fprintf(&b, "%s %s\n", vfs.FormatAttrs(flags), display)
	}

	var list func(display, full string)
	list = func(display, full string) {
		infos, err := e.fs.List(full)
		if err != nil {
			return
		}
		if all {
			show(display+"/.", full)
			show(display+"/..", path.Join(full, ".."))
		}
		for _, fi := range infos {
			if !all && strings.HasPrefix(fi.Name, ".") {
				continue
			}
			child, childFull := display+"/"+fi.Name, path.Join(full, fi.Name)
			show(child, childFull)
			if recursive && fi.IsDir && lines < maxAttrLines {
				fmt.Fprintf(&b, "\n%s:\n", child)
				list(child, childFull)
				b.WriteString("\n")
			}
		}
	}

	for _, name := range files {
		full := path.Clean(absPath(cwd, name))
		fi, ok := e.fs.Resolve(full)
		if !ok {
			fmt.Fprintf(&b, "lsattr: No such file or directory while trying to stat %s\n", name)
			code = 1
			continue
		}
		if fi.IsDir && !dirsOnly {
			list(name, full)
			continue
		}
		show(name, full)
	}
	return []byte(b.String()), code
}

// chattrCmd 仿真 chattr [-pRVf] [-+=aAcCdDeFijmPsStTux] [-v version] files...
func (e *Executor) chattrCmd(ctx *execCtx, cwd string, args []string) ([]byte, int) {
	type modeOp struct {
		op   byte
		bits uint32
	}
	var (
		ops                       []modeOp
		files                     []string
		recursive, verbose, quiet bool
		b                         strings.Builder
		code                      int
	)
	usage := func() ([]byte, int) { return []byte(chattrUsage), 1 }

	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "--":
			files = append(files, args[i+1:]...)
			i = len(args)
		case a == "-p" || a == "-v": // 带一个参数（项目号 / 版本号），本仿真忽略取值
			i++
			if i >= len(args) {
				return usage()
			}
		case len(a) > 1 && a[0] == '-' && strings.Trim(a[1:], "RVf") == "":
			for _, c := range a[1:] {
				switch c {
				case 'R':
					recursive = true
				case 'V':
					verbose = true
				case 'f':
					quiet = true
				}
			}
		case len(a) > 1 && (a[0] == '+' || a[0] == '-' || a[0] == '='):
			var bits uint32
			for j := 1; j < len(a); j++ {
				if !strings.ContainsRune(chattrModeLetters, rune(a[j])) {
					return usage()
				}
				bit, _ := vfs.AttrBit(a[j])
				bits |= bit
			}
			ops = append(ops, modeOp{a[0], bits})
		default:
			files = append(files, a)
		}
	}
	if len(ops) == 0 || len(files) == 0 {
		return usage()
	}
	if verbose {
		b.WriteString("chattr 1.46.5 (30-Dec-2021)\n")
	}

	fail := func(format string, a ...any) {
		code = 1
		if !quiet {
			fmt.Fprintf(&b, format, a...)
		}
	}

	apply := func(display, full string) {
		if noAttrPath(full) {
			fail("chattr: Inappropriate ioctl for device while reading flags on %s\n", display)
			return
		}
		fi, ok := e.fs.Resolve(full)
		old, _ := e.fs.Attrs(full)
		if !ok {
			return
		}
		nf := old
		for _, op := range ops {
			switch op.op {
			case '+':
				nf |= op.bits
			case '-':
				nf &^= op.bits
			case '=':
				nf = op.bits
			}
		}
		// 设置/清除 i、a 需要 CAP_LINUX_IMMUTABLE（root）；普通用户也只能改自己的文件
		if !ctx.user.IsRoot() &&
			((old^nf)&(vfs.AttrImmutable|vfs.AttrAppendOnly) != 0 || fi.Owner != ctx.user.Name) {
			fail("chattr: Operation not permitted while setting flags on %s\n", display)
			return
		}
		if err := e.fs.SetAttrs(full, nf); err != nil {
			fail("chattr: %s while setting flags on %s\n", err, display)
			return
		}
		if verbose {
			now, _ := e.fs.Attrs(full)
			fmt.Fprintf(&b, "Flags of %s set as %s\n", display, vfs.FormatAttrs(now))
		}
	}

	for _, name := range files {
		full := path.Clean(absPath(cwd, name))
		fi, ok := e.fs.Resolve(full)
		if !ok {
			fail("chattr: No such file or directory while trying to stat %s\n", name)
			continue
		}
		apply(name, full)
		if recursive && fi.IsDir {
			// Walk 持读锁期间不能写，先收集再逐个设置
			type target struct{ display, full string }
			var targets []target
			e.fs.Walk(full, func(rel string, _ vfs.FileInfo) bool {
				targets = append(targets, target{strings.TrimSuffix(name, "/") + "/" + rel, path.Join(full, rel)})
				return len(targets) < maxAttrTargets
			})
			for _, t := range targets {
				apply(t.display, t.full)
			}
		}
	}
	return []byte(b.String()), code
}
