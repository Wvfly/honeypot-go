// anti_attack：TCP 反弹代理。
//
// 监听本机一个端口，accept 后取客户端源 IP，反弹连回该源 IP 的同一端口，
// 然后双向透传字节流。蜜罐场景下常作为诱导层：攻击者扫到本机端口，
// 流量被反弹回他自己的同一端口——既不暴露本地真实服务，也能记录来连。
//
// 日志按天滚动到 logs/<base>-YYYY-MM-DD.log；
// 同一文件超过 -log-size 后归档为带时间戳的子文件并 gzip 压缩；
// 超过 -log-age 天的旧文件自动清理。
//
// 用法：
//
//	anti_attack -port 22 -log logs/anti_attack.log -log-level info
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"gopkg.in/natefinch/lumberjack.v2"
)

func main() {
	var (
		port        = flag.Int("port", 22, "本机监听端口；客户端连进来后，反弹连回其源 IP 的同一端口")
		logPath     = flag.String("log", "logs/anti_attack.log", "日志文件路径；按天切分文件名，超阈值时再切子文件并 gzip")
		logLevel    = flag.String("log-level", "info", "日志等级：debug/info/warn/error")
		logSize     = flag.Int("log-size", 100, "单日志文件最大 MB，超出滚动")
		logBackups  = flag.Int("log-backups", 7, "保留几个旧日志文件")
		logAge      = flag.Int("log-age", 30, "旧日志最多保留天数")
		logCompress = flag.Bool("log-compress", true, "是否 gzip 压缩已滚动出去的日志")
	)
	flag.Parse()

	lvl, err := parseLevel(*logLevel)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}

	dir := filepath.Dir(*logPath)
	if dir != "" {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			fmt.Fprintf(os.Stderr, "mkdir log dir: %v\n", err)
			os.Exit(1)
		}
	}
	base := strings.TrimSuffix(filepath.Base(*logPath), filepath.Ext(*logPath))
	w := newDailyRotatingWriter(dir, base, *logSize, *logBackups, *logAge, *logCompress)
	defer w.Close()

	logger := slog.New(slog.NewTextHandler(w, &slog.HandlerOptions{Level: lvl}))
	logger.Info("anti_attack proxy starting",
		"port", *port,
		"log", *logPath,
		"level", *logLevel,
	)

	locals, err := localIPs()
	if err != nil {
		logger.Error("enumerate local IPs failed", "err", err)
		os.Exit(1)
	}
	localSet := &ipSet{ips: locals}
	logger.Info("local IP filter loaded", "count", len(locals))

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	addr := ":" + strconv.Itoa(*port)
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		logger.Error("listen failed", "addr", addr, "err", err)
		os.Exit(1)
	}
	logger.Info("listening", "addr", addr)

	// 收到信号就关 listener，accept 循环退出；已 accept 的连接跑完为止。
	go func() {
		<-ctx.Done()
		_ = ln.Close()
	}()

	for {
		c, err := ln.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				logger.Info("shutdown")
				return
			}
			logger.Warn("accept failed", "err", err)
			continue
		}
		go handleConn(c, *port, localSet, logger)
	}
}

// handleConn 处理单条连接：反弹连回客户端源 IP 的同一端口，然后双向 io.Copy。
func handleConn(c net.Conn, listenPort int, localSet *ipSet, logger *slog.Logger) {
	defer c.Close()

	host, _, err := net.SplitHostPort(c.RemoteAddr().String())
	if err != nil {
		logger.Warn("bad remote addr", "err", err)
		return
	}
	srcIP := net.ParseIP(host)
	if srcIP == nil {
		logger.Warn("parse remote IP failed", "host", host)
		return
	}
	if localSet.contains(srcIP) {
		// 伪源 IP 反射型 DoS 防护：源 IP 命中本机任意网卡地址，反弹会打回自己监听端口。
		logger.Warn("drop connection from local IP (spoofed source)",
			"src", c.RemoteAddr().String())
		return
	}
	target := net.JoinHostPort(host, strconv.Itoa(listenPort))
	upstream, err := net.Dial("tcp", target)
	if err != nil {
		// 攻击者本机该端口通常没人在听，反弹失败属于正常情况，记 warn 即可。
		logger.Warn("dial upstream failed", "target", target, "err", err)
		return
	}
	defer upstream.Close()

	logger.Info("proxy open",
		"client", c.RemoteAddr().String(),
		"upstream", upstream.RemoteAddr().String(),
	)

	upN := &countingReader{r: c}
	downN := &countingReader{r: upstream}
	errc := make(chan error, 2)

	// 客户端 → 上游
	go func() {
		_, e := io.Copy(upstream, upN)
		errc <- e
		if tc, ok := upstream.(*net.TCPConn); ok {
			_ = tc.CloseWrite()
		}
	}()
	// 上游 → 客户端
	go func() {
		_, e := io.Copy(c, downN)
		errc <- e
		if tc, ok := c.(*net.TCPConn); ok {
			_ = tc.CloseWrite()
		}
	}()
	for i := 0; i < 2; i++ {
		<-errc
	}

	logger.Info("proxy close",
		"client", c.RemoteAddr().String(),
		"up_bytes", upN.n,
		"down_bytes", downN.n,
	)
}

// countingReader 包装 io.Reader 累计读字节数。
type countingReader struct {
	r io.Reader
	n int64
}

func (c *countingReader) Read(p []byte) (int, error) {
	m, err := c.r.Read(p)
	c.n += int64(m)
	return m, err
}

// dailyRotatingWriter 在 lumberjack 之上做"按天 + 按 size"双策略滚动：
// 每天切到一个带日期的新文件（anti_attack-2026-09-16.log）；
// 同一天内超 -log-size 时由 lumberjack 滚动为带时间戳的子文件并按 Compress gzip；
// 超过 -log-age 天的旧文件由 lumberjack 自动清理。
type dailyRotatingWriter struct {
	mu       sync.Mutex
	dir      string
	base     string
	maxSize  int
	backups  int
	age      int
	compress bool
	cur      *lumberjack.Logger
	curDate  string
}

func newDailyRotatingWriter(dir, base string, maxSize, backups, age int, compress bool) *dailyRotatingWriter {
	w := &dailyRotatingWriter{
		dir:      dir,
		base:     base,
		maxSize:  maxSize,
		backups:  backups,
		age:      age,
		compress: compress,
	}
	w.rotateIfNeeded(time.Now())
	return w
}

func (w *dailyRotatingWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.rotateIfNeeded(time.Now())
	return w.cur.Write(p)
}

func (w *dailyRotatingWriter) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.cur != nil {
		return w.cur.Close()
	}
	return nil
}

func (w *dailyRotatingWriter) rotateIfNeeded(now time.Time) {
	today := now.Format("2006-01-02")
	if w.cur != nil && w.curDate == today {
		return
	}
	if w.cur != nil {
		_ = w.cur.Close()
	}
	w.cur = &lumberjack.Logger{
		Filename:   filepath.Join(w.dir, w.base+"-"+today+".log"),
		MaxSize:    w.maxSize,
		MaxBackups: w.backups,
		MaxAge:     w.age,
		Compress:   w.compress,
		LocalTime:  true,
	}
	w.curDate = today
}

func parseLevel(s string) (slog.Level, error) {
	switch s {
	case "debug":
		return slog.LevelDebug, nil
	case "info", "":
		return slog.LevelInfo, nil
	case "warn":
		return slog.LevelWarn, nil
	case "error":
		return slog.LevelError, nil
	default:
		return 0, fmt.Errorf("invalid -log-level %q (want debug|info|warn|error)", s)
	}
}

// localIPs 枚举本机所有 unicast 接口地址（不限网卡名——eth0/ens33/wlan0/br-xxx/
// vethxxx/wg0 等都会被 net.InterfaceAddrs 枚举到），并显式补上 loopback
//（net.InterfaceAddrs 按文档不返回 loopback，但攻击者伪源 127.0.0.1 也会触发
// self-loop，所以要手动纳入过滤集）。
func localIPs() ([]net.IP, error) {
	var ips []net.IP

	// 显式补 loopback：net.InterfaceAddrs / Interface.Addrs 都不返回
	ips = append(ips, net.IPv4(127, 0, 0, 1))
	ips = append(ips, net.ParseIP("::1"))

	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return nil, err
	}
	for _, a := range addrs {
		var ip net.IP
		switch v := a.(type) {
		case *net.IPNet:
			ip = v.IP
		case *net.IPAddr:
			ip = v.IP
		default:
			continue
		}
		if ip == nil {
			continue
		}
		// 跳过 multicast（TCP 源不能是多播，纳入过滤无意义）
		if ip.IsMulticast() {
			continue
		}
		ips = append(ips, ip)
	}
	return ips, nil
}

// ipSet 加速 net.IP 的 contains 查询，用 Equal 比较（兼容 IPv4-mapped IPv6 等格式差异）。
type ipSet struct{ ips []net.IP }

func (s *ipSet) contains(ip net.IP) bool {
	if ip == nil {
		return false
	}
	for _, l := range s.ips {
		if l.Equal(ip) {
			return true
		}
	}
	return false
}
