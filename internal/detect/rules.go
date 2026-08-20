package detect

import (
	"net"
	"net/url"
	"strings"
	"time"

	"honeypot-go/internal/event"
)

// Rule 检测规则：事件模式 + 条件 + 加分 + 严重级
type Rule struct {
	Name     string
	Severity string // low / medium / high / critical
	Points   int
	Match    func(ev event.Event, st *connState) bool
}

// rules 内置规则集（后续可配置化）
var rules = []Rule{
	{
		Name: "brute_force_burst", Severity: "high", Points: 30,
		Match: func(ev event.Event, st *connState) bool {
			if ev.Type != event.TypeAuthAttempt {
				return false
			}
			return !eventBool(ev, "success") && st.fails >= 50
		},
	},
	{
		Name: "weak_login_success", Severity: "medium", Points: 20,
		Match: func(ev event.Event, st *connState) bool {
			return ev.Type == event.TypeAuthAttempt && eventBool(ev, "success")
		},
	},
	{
		Name: "post_login_recon", Severity: "high", Points: 30,
		Match: func(ev event.Event, st *connState) bool {
			if ev.Type != event.TypeCommandExecuted {
				return false
			}
			if !st.loggedIn || time.Since(st.loginAt) > 3*time.Second {
				return false
			}
			cmd := strings.ToLower(eventStr(ev, "command"))
			for _, w := range []string{"whoami", "uname", "hostname", "ifconfig"} {
				if strings.Contains(cmd, w) {
					return true
				}
			}
			// id 命令按命令边界匹配（避免 pid/uid 等误报），"id" 单独执行也能命中
			if strings.HasPrefix(cmd, "id") || strings.Contains(cmd, " id") ||
				strings.Contains(cmd, ";id") || strings.Contains(cmd, "&&id") ||
				strings.Contains(cmd, "||id") || strings.Contains(cmd, "&id") ||
				strings.Contains(cmd, "|id") {
				return true
			}
			return false
		},
	},
	{
		Name: "suspicious_download", Severity: "high", Points: 35,
		Match: func(ev event.Event, st *connState) bool {
			if ev.Type != event.TypeDownloadAttempt {
				return false
			}
			u := strings.ToLower(eventStr(ev, "url"))
			for _, ext := range []string{".sh", ".py", ".exe", ".bin", ".elf", ".pl", ".so"} {
				if strings.Contains(u, ext) {
					return true
				}
			}
			if parsed, err := url.Parse(eventStr(ev, "url")); err == nil && parsed.Host != "" {
				if ip := net.ParseIP(hostOnly(parsed.Host)); ip != nil && !ip.IsLoopback() {
					return true // 直接 IP 下载
				}
			}
			return false
		},
	},
	{
		Name: "reverse_shell_attempt", Severity: "critical", Points: 50,
		Match: func(ev event.Event, st *connState) bool {
			if ev.Type != event.TypeCommandExecuted {
				return false
			}
			low := strings.ToLower(eventStr(ev, "command"))
			// ncat/netcat 不包含子串 "nc "，需单独覆盖
			ncLike := strings.Contains(low, "nc ") || strings.Contains(low, "ncat") ||
				strings.Contains(low, "netcat")
			return strings.Contains(low, "mkfifo") ||
				(ncLike && strings.Contains(low, "-l")) ||
				// nc -e / ncat -e / netcat -e：执行命令模式（正连与反连均构成反弹 shell 尝试）。
				// 子串 "-e" 同时覆盖内联形式 -e/bin/sh，且 "-e" 在 nc 命令语境下误报面极小
				(ncLike && strings.Contains(low, "-e")) ||
				strings.Contains(low, "bash -i") ||
				strings.Contains(low, "sh -i") ||
				strings.Contains(low, "socat") ||
				strings.Contains(low, "/dev/tcp/") ||
				strings.Contains(low, "/dev/udp/") ||
				(strings.Contains(low, "python") && strings.Contains(low, "socket")) ||
				(strings.Contains(low, "perl") && strings.Contains(low, "socket")) ||
				strings.Contains(low, "powershell -nop") ||
				strings.Contains(low, "-enc ")
		},
	},
	{
		Name: "persistence_attempt", Severity: "critical", Points: 45,
		Match: func(ev event.Event, st *connState) bool {
			if ev.Type != event.TypeFileWritten {
				return false
			}
			p := strings.ToLower(eventStr(ev, "path"))
			return strings.Contains(p, "authorized_keys") ||
				strings.Contains(p, "crontab") ||
				strings.Contains(p, "rc.local") ||
				strings.Contains(p, "systemd") ||
				strings.Contains(p, "init.d")
		},
	},
	{
		Name: "sensitive_file_read", Severity: "low", Points: 10,
		Match: func(ev event.Event, st *connState) bool {
			if ev.Type != event.TypeCommandExecuted {
				return false
			}
			// 匹配通配符变体（cat /etc/sha*dow、/etc/pass* 等）：展开前原始命令
			// 不含完整路径，故用前缀子串兜底
			low := strings.ToLower(eventStr(ev, "command"))
			for _, s := range []string{
				"/etc/shadow", "/etc/sha", "/etc/passwd", "/etc/pass",
				"/etc/master.passwd", "/etc/group", "/etc/sudoers", "/etc/hosts",
				"getent passwd", "getent shadow",
			} {
				if strings.Contains(low, s) {
					return true
				}
			}
			return false
		},
	},
	{
		Name: "lateral_movement", Severity: "high", Points: 30,
		Match: func(ev event.Event, st *connState) bool {
			if ev.Type != event.TypeConnectAttempt {
				return false
			}
			return isPrivateIP(hostOnly(eventStr(ev, "target")))
		},
	},
}

// severityForScore 按累计风险分定级
func severityForScore(score int) string {
	switch {
	case score >= 80:
		return "critical"
	case score >= 50:
		return "high"
	case score >= 25:
		return "medium"
	default:
		return "low"
	}
}

// --- helpers ---

func eventBool(ev event.Event, key string) bool {
	b, _ := ev.Data[key].(bool)
	return b
}

func eventStr(ev event.Event, key string) string {
	s, _ := ev.Data[key].(string)
	return s
}

// hostOnly 去掉 host:port 里的端口
func hostOnly(h string) string {
	if host, _, err := net.SplitHostPort(h); err == nil {
		return host
	}
	return h
}

func isPrivateIP(host string) bool {
	ip := net.ParseIP(host)
	if ip == nil {
		return false
	}
	if ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsPrivate() {
		return true
	}
	return false
}
