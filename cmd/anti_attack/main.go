// anti_attack：TCP 反弹代理。
//
// 监听本机一个端口，accept 后取客户端源 IP，反弹连回该源 IP 的同一端口，
// 然后双向透传字节流。蜜罐场景下常作为诱导层：攻击者扫到本机端口，
// 流量被反弹回他自己的同一端口——既不暴露本地真实服务，也能记录来连。
//
// 日志写入 -log 指定的活跃文件；跨天时把前一天内容归档为
// <name>-YYYYMMDDTHHMMSS.NNN.log.gz（NNN 为同秒内的滚动序号，从 000 起），
// 同一天内超 -log-size 时由 lumberjack 自滚动，超 -log-age 天的旧归档自动清理。
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

// 子进程标记与就绪管道都用环境变量传递，不走 args：
// 否则子进程 flag.Parse 会撞到未注册的 flag → os.Exit(2)。
const (
	envDaemonChild = "ANTI_ATTACK_DAEMON_CHILD"
	envReadyFD     = "ANTI_ATTACK_READY_FD"
)

// readyPipe 是 daemon 子进程继承自父进程的就绪管道；非 daemon 模式为 nil。
var readyPipe *os.File

// reportReady 通过就绪管道向父进程报告 "OK" 或 "ERR: ..."，随后关闭管道（只报告一次）。
func reportReady(msg string) {
	if readyPipe == nil {
		return
	}
	_, _ = readyPipe.WriteString(msg + "\n")
	_ = readyPipe.Close()
	readyPipe = nil
}

// fatal 打印错误并退出；在 daemon 子进程里同时通过就绪管道把原因带给父进程，
// 这样 `-d` 启动失败时终端上能直接看到原因，而不是只有一个 exit status。
func fatal(code int, format string, a ...any) {
	msg := fmt.Sprintf(format, a...)
	fmt.Fprintln(os.Stderr, msg)
	reportReady("ERR: " + msg)
	os.Exit(code)
}

// childArgs 按当前解析结果重建传给 daemon 子进程的参数：
// 逐个 flag 显式传值（去掉 -d/-daemon），不依赖用户当初怎么写的（-d、-daemon、-d=true…），
// 也保证父进程转好的绝对路径会原样传下去。
func childArgs() []string {
	var args []string
	flag.VisitAll(func(f *flag.Flag) {
		if f.Name == "d" || f.Name == "daemon" {
			return
		}
		args = append(args, "-"+f.Name+"="+f.Value.String())
	})
	return args
}

func main() {
	var (
		port        = flag.Int("port", 22, "本机监听端口；客户端连进来后，代理连回其源 IP 的同一端口")
		logPath     = flag.String("log", "logs/anti_attack.log", "活跃日志文件名；归档为 <name>-YYYY-MM-DDTHH-MM-SS.mmm.log.gz（时间戳为轮转时刻，mmm 为毫秒）")
		logLevel    = flag.String("log-level", "info", "日志等级：debug/info/warn/error")
		logSize     = flag.Int("log-size", 100, "单日志文件最大 MB，超出滚动")
		logBackups  = flag.Int("log-backups", 0, "保留几个旧日志文件；0 表示不限个数，仅按 -log-age 清理")
		logAge      = flag.Int("log-age", 30, "旧日志最多保留天数（与 -log-backups 任一先达到即删除）")
		logCompress = flag.Bool("log-compress", true, "是否 gzip 压缩已滚动出去的日志")
		daemon      = flag.Bool("daemon", false, "后台运行：fork 出子进程脱离终端，仅 Linux；子进程就绪后父进程才返回，失败原因直接打印；panic 等 stderr 输出写入 <-log 去掉扩展名>.stderr")
		pidfile     = flag.String("pidfile", "logs/anti_attack.pid", "PID 文件路径；成功监听后写入，正常退出时删除；daemon 模式下写入失败视为启动失败；留空则不写")
	)
	flag.BoolVar(daemon, "d", false, "同 -daemon")

	isChild := os.Getenv(envDaemonChild) == "1"
	if isChild {
		if fd, err := strconv.Atoi(os.Getenv(envReadyFD)); err == nil && fd > 2 {
			readyPipe = os.NewFile(uintptr(fd), "ready")
		}
	}

	flag.Parse()

	// —— 参数校验：放在 fork 之前，错误直接显示在终端 ——
	if *port < 1 || *port > 65535 {
		fatal(2, "invalid -port %d (want 1-65535)", *port)
	}
	lvl, err := parseLevel(*logLevel)
	if err != nil {
		fatal(2, "%v", err)
	}

	daemonParent := *daemon && !isChild
	if daemonParent {
		// daemon 不切换工作目录，从不同目录（cron/systemd 的 cwd 常是 /）启动会落到不同位置，
		// 所以 fork 前统一转成绝对路径，再原样传给子进程。
		if *logPath, err = filepath.Abs(*logPath); err != nil {
			fatal(1, "resolve -log: %v", err)
		}
		if *pidfile != "" {
			if *pidfile, err = filepath.Abs(*pidfile); err != nil {
				fatal(1, "resolve -pidfile: %v", err)
			}
		}
	}

	// 日志目录和 pidfile 目录都要建（两者可以不在同一目录）
	if err := os.MkdirAll(filepath.Dir(*logPath), 0o755); err != nil {
		fatal(1, "mkdir log dir: %v", err)
	}
	if *pidfile != "" {
		if err := os.MkdirAll(filepath.Dir(*pidfile), 0o755); err != nil {
			fatal(1, "mkdir pidfile dir: %v", err)
		}
	}

	if daemonParent {
		stderrPath := strings.TrimSuffix(*logPath, filepath.Ext(*logPath)) + ".stderr"
		pid, err := daemonize(childArgs(), stderrPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "daemonize failed: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("anti_attack daemonized, pid=%d\n  log:    %s\n  stderr: %s\n", pid, *logPath, stderrPath)
		if *pidfile != "" {
			fmt.Printf("  pidfile: %s\n", *pidfile)
		}
		os.Exit(0)
	}

	// daemon 子进程忽略 SIGHUP：父 shell 退出时所有 jobs 会收到 SIGHUP，
	// daemon 子进程应继续运行而不是跟着退出。
	if isChild {
		signal.Ignore(syscall.SIGHUP)
	}

	// —— 先监听，再碰日志和 pidfile ——
	// 端口被占用时，失败的实例不应该污染已运行实例的日志，更不能覆盖它的 pidfile。
	locals, err := localIPs()
	if err != nil {
		fatal(1, "enumerate local IPs failed: %v", err)
	}
	localSet := &ipSet{nets: locals}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	addr := ":" + strconv.Itoa(*port)
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		fatal(1, "listen %s failed: %v", addr, err)
	}

	w := newDailyRotatingWriter(*logPath, *logSize, *logBackups, *logAge, *logCompress)
	defer w.Close()

	logger := slog.New(slog.NewTextHandler(w, &slog.HandlerOptions{Level: lvl}))
	logger.Info("anti_attack proxy starting",
		"port", *port,
		"log", *logPath,
		"level", *logLevel,
		"daemon", isChild,
	)
	logger.Info("local IP filter loaded", "count", len(locals))
	logger.Info("listening", "addr", addr)

	if *pidfile != "" {
		if err := os.WriteFile(*pidfile, []byte(strconv.Itoa(os.Getpid())+"\n"), 0o644); err != nil {
			if isChild {
				// daemon 模式下 pidfile 是唯一的控制入口，写不进去就等于无法管理，按启动失败处理
				logger.Error("write pidfile failed", "err", err, "path", *pidfile)
				_ = ln.Close()
				fatal(1, "write pidfile %s failed: %v", *pidfile, err)
			}
			logger.Warn("write pidfile failed", "err", err, "path", *pidfile)
		} else {
			logger.Info("pidfile written", "path", *pidfile)
			defer removePidfile(*pidfile, logger)
		}
	}

	// 监听成功、日志和 pidfile 都就绪：通知父进程可以返回了
	reportReady("OK")

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

// removePidfile 仅当 pidfile 里记的还是自己的 PID 时才删除，
// 避免误删别的实例（例如换了端口的另一个实例）写的 pidfile。
func removePidfile(path string, logger *slog.Logger) {
	b, err := os.ReadFile(path)
	if err != nil {
		return
	}
	if strings.TrimSpace(string(b)) != strconv.Itoa(os.Getpid()) {
		return
	}
	if err := os.Remove(path); err != nil {
		logger.Warn("remove pidfile failed", "err", err, "path", path)
		return
	}
	logger.Info("pidfile removed", "path", path)
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
		logger.Warn("drop connection from local IP (spoofed source)",
			"src", c.RemoteAddr().String())
		return
	}
	target := net.JoinHostPort(host, strconv.Itoa(listenPort))
	upstream, err := net.Dial("tcp", target)
	if err != nil {
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

// dailyRotatingWriter 在 lumberjack 之上做"按天"触发。
//
// 全程只持有一个 lumberjack.Logger，跨天时对它调用 Rotate()（归档当前文件并
// 新建同名活跃文件）。不要在跨天时重建 Logger：每个 Logger 各带一个后台压缩
// 协程，旧实例 Rotate 触发的压缩与新实例首次写入触发的压缩会并发处理同一个
// 备份文件，后完成的一方 os.Remove(src) 失败后会把先完成方刚生成的 .gz 一并
// 删掉，导致整天日志既无源文件也无归档（日志越大，两个压缩协程重叠得越久，
// 越容易触发）。
//
// 归档的触发时机：
//  1. 启动时：活跃文件非空且最后修改日期不是今天，说明上次运行跨过了天，先归档；
//  2. 每次 Write 前：日期变了就归档；
//  3. 每天本地 0 点的定时器：即使当天 0 点之后没有日志写入也按时归档，
//     归档文件名里的时间戳（即轮转时刻）因此接近 00:00:00，与内容所属日期一致。
//
// 同一文件超过 -log-size 时由 lumberjack 自己做 size-based 滚动。
type dailyRotatingWriter struct {
	mu      sync.Mutex
	lj      *lumberjack.Logger
	curDate string
	timer   *time.Timer
	closed  bool
}

const dateLayout = "2006-01-02"

func newDailyRotatingWriter(filename string, maxSize, backups, age int, compress bool) *dailyRotatingWriter {
	w := &dailyRotatingWriter{
		lj: &lumberjack.Logger{
			Filename:   filename,
			MaxSize:    maxSize,
			MaxBackups: backups,
			MaxAge:     age,
			Compress:   compress,
			LocalTime:  true,
		},
	}
	now := time.Now()
	w.curDate = now.Format(dateLayout)
	// 已有非空的旧文件：以其最后修改日期作为它所属的日期，
	// 若不是今天，下面的 rotateIfNeeded 会立刻把它归档。
	if fi, err := os.Stat(filename); err == nil && fi.Size() > 0 {
		w.curDate = fi.ModTime().Format(dateLayout)
	}
	w.rotateIfNeeded(now)
	w.scheduleMidnight(now)
	return w
}

// rotateIfNeeded 在日期变化时归档当前活跃文件。调用方须持有 w.mu（构造函数除外）。
func (w *dailyRotatingWriter) rotateIfNeeded(now time.Time) {
	today := now.Format(dateLayout)
	if w.curDate == today {
		return
	}
	// 空文件（或文件不存在）不必归档，避免产生空的 .gz
	if fi, err := os.Stat(w.lj.Filename); err == nil && fi.Size() > 0 {
		if err := w.lj.Rotate(); err != nil {
			// 不更新 curDate：下次写入 / 定时器触发时会重试，而不是静默等到明天
			fmt.Fprintf(os.Stderr, "log rotate failed: %v\n", err)
			return
		}
	}
	w.curDate = today
}

// scheduleMidnight 安排下一个本地 0 点的轮转检查。调用方须持有 w.mu（构造函数除外）。
func (w *dailyRotatingWriter) scheduleMidnight(now time.Time) {
	next := time.Date(now.Year(), now.Month(), now.Day()+1, 0, 0, 0, 0, now.Location())
	w.timer = time.AfterFunc(next.Sub(now), func() {
		w.mu.Lock()
		defer w.mu.Unlock()
		if w.closed {
			return
		}
		n := time.Now()
		w.rotateIfNeeded(n)
		w.scheduleMidnight(n)
	})
}

func (w *dailyRotatingWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.rotateIfNeeded(time.Now())
	return w.lj.Write(p)
}

func (w *dailyRotatingWriter) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.closed = true
	if w.timer != nil {
		w.timer.Stop()
	}
	return w.lj.Close()
}

func localIPs() ([]*net.IPNet, error) {
	var nets []*net.IPNet

	// 显式纳入 loopback 整段：net.InterfaceAddrs 按文档不返回 loopback
	_, loopback4, _ := net.ParseCIDR("127.0.0.0/8")
	nets = append(nets, loopback4)
	_, loopback6, _ := net.ParseCIDR("::1/128")
	nets = append(nets, loopback6)

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
		// 单 IP 转成 /32 或 /128 的 IPNet，便于统一 Contains 比较
		var mask net.IPMask
		if ip.To4() != nil {
			mask = net.CIDRMask(32, 32)
		} else {
			mask = net.CIDRMask(128, 128)
		}
		nets = append(nets, &net.IPNet{IP: ip, Mask: mask})
	}
	return nets, nil
}

// ipSet 用 IPNet.Contains 做命中判断（兼容 IPv4-mapped IPv6 等格式差异，
// 自动覆盖整段 CIDR，不只精确 IP）。
type ipSet struct{ nets []*net.IPNet }

func (s *ipSet) contains(ip net.IP) bool {
	if ip == nil {
		return false
	}
	for _, n := range s.nets {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}
