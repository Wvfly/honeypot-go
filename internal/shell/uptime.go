package shell

import (
	"fmt"
	"strings"
	"time"

	"honeypot-go/internal/vfs"
)

func plural(n int) string {
	if n == 1 {
		return ""
	}
	return "s"
}

// upFragment 生成 uptime 头部 "up" 之后的运行时长，格式与 procps-ng 一致：
// "7 days,  3:42" / " 3:42"（不足一天）/ "42 min"（不足一小时）。
func upFragment(d time.Duration) string {
	mins := int(d / time.Minute)
	days, hours, m := mins/1440, mins%1440/60, mins%60
	var s string
	if days > 0 {
		s = fmt.Sprintf("%d day%s, ", days, plural(days))
	}
	if hours > 0 {
		s += fmt.Sprintf("%2d:%02d", hours, m)
	} else {
		s += fmt.Sprintf("%d min", m)
	}
	return s
}

// uptimeHeader uptime/w/top 共用的头部（不含行首空格或 "top - " 前缀）。
// 运行时长取自 vfs.Uptime，与 /proc/uptime、/proc/stat 的 btime 同源，互不矛盾。
func uptimeHeader(now time.Time, up time.Duration) string {
	return fmt.Sprintf("%s up %s,  1 user,  load average: 0.00, 0.01, 0.05", now.Format("15:04:05"), upFragment(up))
}

// prettyUptime 对应 uptime -p："up 1 week, 3 hours, 42 minutes"（为 0 的周/天/时省略，分钟总是显示）
func prettyUptime(d time.Duration) string {
	mins := int(d / time.Minute)
	var parts []string
	add := func(n int, unit string) { parts = append(parts, fmt.Sprintf("%d %s%s", n, unit, plural(n))) }
	if w := mins / (7 * 1440); w > 0 {
		add(w, "week")
	}
	if dd := mins / 1440 % 7; dd > 0 {
		add(dd, "day")
	}
	if h := mins % 1440 / 60; h > 0 {
		add(h, "hour")
	}
	add(mins%60, "minute")
	return "up " + strings.Join(parts, ", ")
}

const uptimeHelp = `
Usage:
 uptime [options]

Options:
 -p, --pretty   show uptime in pretty format
 -h, --help     display this help and exit
 -s, --since    system up since
 -V, --version  output version information and exit

For more details see uptime(1).
`

// uptimeCmd 仿真 uptime：默认 / -p / -s / -h / -V
func (e *Executor) uptimeCmd(args []string) []byte {
	up := vfs.Uptime()
	for _, a := range args {
		switch a {
		case "-p", "--pretty":
			return []byte(prettyUptime(up) + "\n")
		case "-s", "--since":
			return []byte(time.Now().Add(-up).Format("2006-01-02 15:04:05") + "\n")
		case "-V", "--version":
			return []byte("uptime from procps-ng 3.3.17\n")
		case "-h", "--help":
			return []byte(uptimeHelp)
		}
		if strings.HasPrefix(a, "--") {
			return []byte(fmt.Sprintf("uptime: unrecognized option '%s'\n%s", a, uptimeHelp))
		}
		if strings.HasPrefix(a, "-") && len(a) > 1 {
			return []byte(fmt.Sprintf("uptime: invalid option -- '%c'\n%s", a[1], uptimeHelp))
		}
	}
	return []byte(" " + uptimeHeader(time.Now(), up) + "\n")
}
