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
	target := host(args)
	v.recordDownload(sessionID, "curl", target)
	body := "#!/bin/bash\n# (download decoy)\n"
	return []byte(fmt.Sprintf("  %% Total    %% Received %% Xferd  Average Speed   Time    Time     Time  Current\n                                 Dload  Upload   Total   Spent    Left  Speed\n100   %d  100   %d    0     0   %d      0      0:00:00 --:--:--     0   %d\n",
		len(body), len(body), len(body)*2, len(body)*2))
}

func (v *VNet) wget(sessionID string, args []string) []byte {
	target := host(args)
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
	target := host(args)
	// nc 参数如: nc -lvp 4444 / nc 10.0.0.5 4444
	port := ""
	for i, a := range args {
		if a == "-p" && i+1 < len(args) {
			port = args[i+1]
		} else if !strings.HasPrefix(a, "-") && i > 0 {
			if target == "" {
				target = a
			} else if port == "" && isAllDigits(a) {
				port = a
			}
		}
	}
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
