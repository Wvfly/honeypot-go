package shell

import (
	"fmt"
	"hash/fnv"
	"strconv"
	"strings"
	"time"
)

// Identity 会话的登录身份：SSH 认证时的用户名 + VFS /etc/passwd 里对应的条目。
// prompt、whoami、id、env、$HOME/$USER、who/w/ps、crontab 等都从这里取值，
// 保证攻击者看到的身份与 cat /etc/passwd 一致，而不是一律显示 root。
type Identity struct {
	Name   string
	UID    int
	GID    int
	Home   string
	Groups string // id 输出里 groups= 字段，如 "1000(ubuntu)"
}

// IsRoot 是否为超级用户
func (id Identity) IsRoot() bool { return id.UID == 0 }

// PromptChar 提示符结尾字符：root 为 #，普通用户为 $
func (id Identity) PromptChar() string {
	if id.IsRoot() {
		return "#"
	}
	return "$"
}

// rootIdentity root 身份（同时作为 sudo 提权后的执行身份、未绑定用户时的默认值）
func rootIdentity() Identity {
	return Identity{Name: "root", UID: 0, GID: 0, Home: "/root", Groups: "0(root)"}
}

// maxUserNameLen 与 Linux useradd 的用户名长度上限一致
const maxUserNameLen = 32

// SanitizeUsername 清洗登录用户名。用户名来自攻击者，会被拼进 prompt（写入 ttyrec，
// 运营侧用 ttyshow 回放）和 crontab 路径，因此只保留 [A-Za-z0-9._-]，
// 去掉开头的 "." 和 "-"（避免 ".." 路径穿越与被当成命令行选项），并限制长度。
// 清洗后为空则返回 "user"。
func SanitizeUsername(name string) string {
	var b strings.Builder
	for _, r := range name {
		if b.Len() >= maxUserNameLen {
			break
		}
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9',
			r == '_', r == '-', r == '.':
			b.WriteRune(r)
		}
	}
	s := strings.TrimLeft(b.String(), ".-")
	if s == "" {
		return "user"
	}
	return s
}

// ResolveUser 按用户名解析身份：优先读 VFS 的 /etc/passwd（与攻击者 cat 到的一致）；
// 蜜罐会放行任意用户名登录，passwd 里查不到时合成一个普通用户身份。
func (e *Executor) ResolveUser(name string) Identity {
	name = SanitizeUsername(name)
	if content, err := e.fs.ReadFile("/etc/passwd"); err == nil {
		if id, ok := parsePasswdEntry(content, name); ok {
			return id
		}
	}
	if name == "root" { // passwd 被改坏时 root 仍要是 root
		return rootIdentity()
	}
	return synthIdentity(name)
}

// parsePasswdEntry 从 /etc/passwd 内容中解析指定用户（name:x:uid:gid:gecos:home:shell）
func parsePasswdEntry(content []byte, name string) (Identity, bool) {
	for _, line := range strings.Split(string(content), "\n") {
		f := strings.Split(line, ":")
		if len(f) < 6 || f[0] != name {
			continue
		}
		uid, err1 := strconv.Atoi(f[2])
		gid, err2 := strconv.Atoi(f[3])
		if err1 != nil || err2 != nil {
			continue
		}
		return Identity{Name: name, UID: uid, GID: gid, Home: f[5], Groups: groupsString(name, uid, gid)}, true
	}
	return Identity{}, false
}

// synthIdentity 为 passwd 中不存在的用户名合成身份：uid/gid 由用户名哈希得出（同名稳定），
// 落在 1100 以上，避开预置用户（1000 起顺序分配）。
func synthIdentity(name string) Identity {
	h := fnv.New32a()
	h.Write([]byte(name))
	uid := 1100 + int(h.Sum32()%50000)
	return Identity{Name: name, UID: uid, GID: uid, Home: "/home/" + name, Groups: groupsString(name, uid, uid)}
}

// groupsString 生成 id 命令 groups= 字段（Ubuntu 默认每个用户有同名私有组）
func groupsString(name string, uid, gid int) string {
	if uid == 0 {
		return "0(root)"
	}
	return fmt.Sprintf("%d(%s)", gid, name)
}

// SetUser 绑定会话的登录用户并返回解析出的身份，会话创建时调用一次。
// 身份存放在会话级状态里，Execute 每次按 sessionID 取用，无需改动 Execute 签名。
func (e *Executor) SetUser(sessionID, name string) Identity {
	id := e.ResolveUser(name)
	e.stMu.Lock()
	defer e.stMu.Unlock()
	st := e.states[sessionID]
	if st == nil {
		st = &sessionState{}
		e.states[sessionID] = st
	}
	st.user = id
	return id
}

// identityFor 返回会话身份；未绑定用户的会话（如单测直接调 Execute）默认 root，保持旧行为
func (e *Executor) identityFor(sessionID string) Identity {
	e.stMu.Lock()
	defer e.stMu.Unlock()
	if st := e.states[sessionID]; st != nil && st.user.Name != "" {
		return st.user
	}
	return rootIdentity()
}

// idCmd 仿真 id：支持 -u/-g/-G/-n/-r 组合和 `id <user>`
func (e *Executor) idCmd(cur Identity, args []string) []byte {
	target := cur
	var showU, showG, showAllG, names bool
	for _, a := range args {
		if strings.HasPrefix(a, "-") && len(a) > 1 && !strings.HasPrefix(a, "--") {
			for _, c := range a[1:] {
				switch c {
				case 'u':
					showU = true
				case 'g':
					showG = true
				case 'G':
					showAllG = true
				case 'n':
					names = true
				}
			}
			continue
		}
		if strings.HasPrefix(a, "-") { // 长选项忽略
			continue
		}
		content, _ := e.fs.ReadFile("/etc/passwd")
		id, ok := parsePasswdEntry(content, a)
		if !ok {
			return []byte(fmt.Sprintf("id: '%s': no such user\n", a))
		}
		target = id
	}
	switch {
	case showU && names:
		return []byte(target.Name + "\n")
	case showU:
		return []byte(strconv.Itoa(target.UID) + "\n")
	case showG && names:
		return []byte(groupName(target) + "\n")
	case showG:
		return []byte(strconv.Itoa(target.GID) + "\n")
	case showAllG && names:
		return []byte(groupName(target) + "\n")
	case showAllG:
		return []byte(strconv.Itoa(target.GID) + "\n")
	}
	return []byte(fmt.Sprintf("uid=%d(%s) gid=%d(%s) groups=%s\n",
		target.UID, target.Name, target.GID, groupName(target), target.Groups))
}

// groupName 主组名：root 为 root，其余为同名私有组
func groupName(id Identity) string {
	if id.IsRoot() {
		return "root"
	}
	return id.Name
}

// psUID 按 ps 的 UID 列规则显示用户名：超过 8 个字符截断为 7 个字符加 "+"
func psUID(name string) string {
	if len(name) > 8 {
		return name[:7] + "+"
	}
	return name
}

// psFull 仿真 ps -ef / ps -aux。root 保持原有输出；普通用户按真实 sshd 的
// 权限分离进程模型显示：root 的 "sshd: 用户 [priv]" + 该用户自己的 sshd/bash/ps。
func psFull(user Identity) []byte {
	if user.IsRoot() {
		return []byte(`UID          PID    PPID  C STIME TTY          TIME CMD
root           1       0  0 00:00 ?        00:00:02 /sbin/init
root         378       1  0 00:00 ?        00:00:00 /usr/sbin/sshd -D
root         402     378  0 00:00 ?        00:00:00 sshd: root@pts/0
root         403     402  0 00:00 pts/0    00:00:00 -bash
root         410     403  0 00:00 pts/0    00:00:00 ps -ef
`)
	}
	u := psUID(user.Name)
	var b strings.Builder
	b.WriteString("UID          PID    PPID  C STIME TTY          TIME CMD\n")
	row := func(uid string, pid, ppid int, tty, cpu, cmd string) {
		fmt.Fprintf(&b, "%-8s %7d %7d  0 00:00 %-8s %s %s\n", uid, pid, ppid, tty, cpu, cmd)
	}
	row("root", 1, 0, "?", "00:00:02", "/sbin/init")
	row("root", 378, 1, "?", "00:00:00", "/usr/sbin/sshd -D")
	row("root", 402, 378, "?", "00:00:00", "sshd: "+user.Name+" [priv]")
	row(u, 431, 402, "?", "00:00:00", "sshd: "+user.Name+"@pts/0")
	row(u, 432, 431, "pts/0", "00:00:00", "-bash")
	row(u, 440, 432, "pts/0", "00:00:00", "ps -ef")
	return []byte(b.String())
}

// whoLine 仿真 who：当前会话所属用户
func whoLine(user Identity) []byte {
	return []byte(fmt.Sprintf("%-8s %-12s %s (10.0.2.15)\n", user.Name, "pts/0", time.Now().Format("2006-01-02 15:04")))
}

// wText 仿真 w：当前会话所属用户
func wText(user Identity) []byte {
	return []byte(fmt.Sprintf(" %s up 7 days,  1 user,  load average: 0.00, 0.01, 0.05\n"+
		"USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT\n"+
		"%-8s pts/0    10.0.2.5         08:12    2.00s  0.05s  0.01s -bash\n",
		time.Now().Format("15:04:05"), user.Name))
}
