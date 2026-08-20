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
			for _, w := range []string{"whoami", "uname", "id ", "hostname", "ifconfig"} {
				if strings.Contains(cmd, w) {
					return true
				}
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
			return strings.Contains(low, "mkfifo") ||
				(strings.Contains(low, "nc ") && strings.Contains(low, "-l")) ||
				strings.Contains(low, "bash -i") ||
				strings.Contains(low, "sh -i") ||
				strings.Contains(low, "socat")
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
			cmd := eventStr(ev, "command")
			return strings.Contains(cmd, "/etc/shadow") || strings.Contains(cmd, "/etc/passwd")
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
