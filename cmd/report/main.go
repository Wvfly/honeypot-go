// report 蜜罐活动看板：一个独立部署的 HTTP 服务，只读打开蜜罐的 SQLite 库文件，
// 把聚合统计渲染成网页看板（概览卡片、每日趋势、Top IP/用户名/密码/命令、告警等），
// 浏览器访问即可，页面按 -refresh 间隔自动刷新，也可用 ?since=24h 等参数切换统计范围。
//
// 聚合与渲染逻辑在 internal/report 包，本文件只做参数解析、HTTP 路由和缓存。
//
// 用法:
//
//	go run ./cmd/report -db data/honeypot.db -listen 127.0.0.1:8080
//	go run ./cmd/report -once -out report.html          # 不起服务，生成一次静态 HTML
package main

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"sync"
	"syscall"
	"time"

	"honeypot-go/internal/report"

	_ "modernc.org/sqlite"
)

// dateLayouts -from/-to 支持的输入格式，按顺序尝试
var dateLayouts = []string{"2006-01-02", time.RFC3339, "2006-01-02 15:04:05"}

// server 看板 HTTP 服务：持有只读数据库句柄和一份带 TTL 的报表缓存
type server struct {
	db *sql.DB
	// refreshSec 页面自动刷新秒数（注入模板），同时作为缓存 TTL：
	// 页面最快 refreshSec 刷新一次，缓存比它更细没有意义
	refreshSec int
	// defaultTop 未带 ?top= 参数时使用的 TopN；带参数时被夹在 [1, maxTopN]
	defaultTop int

	mu    sync.Mutex
	cache map[report.Options]cacheEntry
}

const maxTopN = 100

type cacheEntry struct {
	at   time.Time
	rpt  report.Report
	html []byte // 渲染结果按 Options+refreshSec 缓存，TTL 内直接复用
	json []byte
}

func main() {
	dbPath := flag.String("db", "data/honeypot.db", "sqlite 数据库路径（只读打开，可与运行中的蜜罐共用）")
	listen := flag.String("listen", "127.0.0.1:8080", "HTTP 监听地址；对外暴露请自行加防火墙/反代鉴权")
	refresh := flag.Duration("refresh", 30*time.Second, "看板自动刷新间隔（也是报表缓存 TTL），0 表示关闭自动刷新")
	top := flag.Int("top", 10, "各类 Top 列表默认显示多少条（请求可用 ?top= 覆盖）")
	once := flag.Bool("once", false, "不起 HTTP 服务，生成一次静态 HTML 后退出")
	out := flag.String("out", "", "配合 -once：输出的 HTML 文件路径（默认 report_<时间戳>.html）")
	since := flag.Duration("since", 0, "配合 -once：只统计最近这段时间，如 24h、168h")
	from := flag.String("from", "", "配合 -once：统计范围起点（含），格式 2006-01-02 或完整时间戳")
	to := flag.String("to", "", "配合 -once：统计范围终点（不含），格式同 -from")
	flag.Parse()

	db, err := openDB(*dbPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	defer db.Close()

	if *once {
		if err := runOnce(db, *out, *since, *from, *to, *top); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		return
	}

	s := &server{db: db, refreshSec: int(refresh.Seconds()), defaultTop: *top, cache: map[report.Options]cacheEntry{}}
	mux := http.NewServeMux()
	mux.HandleFunc("/", s.handleIndex)
	mux.HandleFunc("/report", s.handleJSON)
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("ok")) })
	srv := &http.Server{
		Addr:              *listen,
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
	}

	go func() {
		fmt.Printf("蜜罐活动看板已启动: http://%s/  (db=%s, 刷新间隔 %s)\n", *listen, *dbPath, *refresh)
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			fmt.Fprintln(os.Stderr, "HTTP 服务退出:", err)
			os.Exit(1)
		}
	}()

	// Ctrl+C / kill 优雅退出
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)
	<-stop
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = srv.Shutdown(ctx)
	fmt.Println("看板服务已停止")
}

// openDB 以只读模式打开数据库，并显式确认 connections 表存在。
// SQLite 打开不存在的文件会直接创建一个空库而不报错，所以只 Ping 不够；
// mode=ro 也避免了看板进程意外创建/写坏库文件。
func openDB(path string) (*sql.DB, error) {
	if _, err := os.Stat(path); err != nil {
		return nil, fmt.Errorf("数据库文件不可用: %w", err)
	}
	dsn := "file:" + filepath.ToSlash(path) + "?mode=ro"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("打开数据库失败: %w", err)
	}
	var exists int
	if err := db.QueryRow(`SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='connections'`).Scan(&exists); err != nil {
		db.Close()
		return nil, fmt.Errorf("连接数据库失败: %w", err)
	}
	if exists == 0 {
		db.Close()
		return nil, fmt.Errorf("数据库 %s 里没有 connections 表，请确认 -db 路径是否正确", path)
	}
	return db, nil
}

// ---- HTTP 处理 ----

func (s *server) handleIndex(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	opts, view, err := s.parseRequest(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	e, err := s.report(opts, view)
	if err != nil {
		http.Error(w, "生成报表失败: "+err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write(e.html)
}

func (s *server) handleJSON(w http.ResponseWriter, r *http.Request) {
	opts, view, err := s.parseRequest(r)
	if err != nil {
		writeJSONError(w, err.Error())
		return
	}
	e, err := s.report(opts, view)
	if err != nil {
		writeJSONError(w, "生成报表失败: "+err.Error())
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	_, _ = w.Write(e.json)
}

func writeJSONError(w http.ResponseWriter, msg string) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(http.StatusInternalServerError)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": msg})
}

// parseRequest 解析查询参数（since/from/to/top）并做校验，返回聚合选项和看板视图参数。
// since 与 from/to 互斥，规则与参考实现的命令行一致。
func (s *server) parseRequest(r *http.Request) (report.Options, report.View, error) {
	q := r.URL.Query()
	sinceStr := q.Get("since")
	fromStr, toStr := q.Get("from"), q.Get("to")
	if sinceStr != "" && (fromStr != "" || toStr != "") {
		return report.Options{}, report.View{}, errors.New("since 不能和 from/to 同时使用")
	}
	opts := report.Options{TopN: s.defaultTop}
	if v := q.Get("top"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 {
			return report.Options{}, report.View{}, fmt.Errorf("top 参数无效: %q（应为 1~%d 的整数）", v, maxTopN)
		}
		if n > maxTopN {
			n = maxTopN
		}
		opts.TopN = n
	}
	if sinceStr != "" {
		d, err := time.ParseDuration(sinceStr)
		if err != nil || d <= 0 {
			return report.Options{}, report.View{}, fmt.Errorf("since 参数无效: %q（应形如 24h、168h）", sinceStr)
		}
		opts.From = time.Now().Add(-d)
	}
	if fromStr != "" {
		t, err := parseDate(fromStr)
		if err != nil {
			return report.Options{}, report.View{}, fmt.Errorf("from: %w", err)
		}
		opts.From = t
	}
	if toStr != "" {
		t, err := parseDate(toStr)
		if err != nil {
			return report.Options{}, report.View{}, fmt.Errorf("to: %w", err)
		}
		opts.To = t
	}
	if !opts.From.IsZero() && !opts.To.IsZero() && !opts.To.After(opts.From) {
		return report.Options{}, report.View{}, errors.New("to 必须晚于 from")
	}
	view := report.View{
		RefreshSec: s.refreshSec,
		Since:      sinceStr,
		TopN:       opts.TopN,
		RangeLabel: report.RangeLabel(sinceStr, fromStr, toStr),
	}
	return opts, view, nil
}

// report 带 TTL 缓存地生成报表：since 每次算出的 From 都不同，为避免缓存永远不命中，
// 缓存键里的 From/To 按分钟取整（误差小于刷新间隔，可接受）。
func (s *server) report(opts report.Options, view report.View) (cacheEntry, error) {
	key := opts
	key.From = opts.From.Truncate(time.Minute)
	key.To = opts.To.Truncate(time.Minute)

	ttl := time.Duration(s.refreshSec) * time.Second
	if ttl < 5*time.Second {
		ttl = 5 * time.Second // refresh=0（关自动刷新）时也保留短缓存，防手工连点打爆磁盘
	}
	s.mu.Lock()
	e, ok := s.cache[key]
	s.mu.Unlock()
	if ok && time.Since(e.at) < ttl {
		return e, nil
	}

	rpt, err := report.Generate(s.db, opts)
	if err != nil {
		return cacheEntry{}, err
	}
	view.Report = rpt
	e = cacheEntry{at: time.Now(), rpt: rpt}
	var buf bytes.Buffer
	if err := report.Render(&buf, view); err != nil {
		return cacheEntry{}, err
	}
	e.html = buf.Bytes()
	if e.json, err = json.Marshal(rpt); err != nil {
		return cacheEntry{}, err
	}
	s.mu.Lock()
	if len(s.cache) > 64 { // 参数组合理论上无限，简单粗暴地整体清空，蜜罐场景足够
		s.cache = map[report.Options]cacheEntry{}
	}
	s.cache[key] = e
	s.mu.Unlock()
	return e, nil
}

// ---- -once 静态导出 ----

func runOnce(db *sql.DB, out string, since time.Duration, from, to string, top int) error {
	if since > 0 && (from != "" || to != "") {
		return errors.New("-since 不能和 -from/-to 同时使用")
	}
	opts := report.Options{TopN: top}
	if since > 0 {
		opts.From = time.Now().Add(-since)
	}
	if from != "" {
		t, err := parseDate(from)
		if err != nil {
			return fmt.Errorf("-from: %w", err)
		}
		opts.From = t
	}
	if to != "" {
		t, err := parseDate(to)
		if err != nil {
			return fmt.Errorf("-to: %w", err)
		}
		opts.To = t
	}
	if !opts.From.IsZero() && !opts.To.IsZero() && !opts.To.After(opts.From) {
		return errors.New("-to 必须晚于 -from")
	}

	rpt, err := report.Generate(db, opts)
	if err != nil {
		return fmt.Errorf("生成报表失败: %w", err)
	}
	outPath := out
	if outPath == "" {
		outPath = fmt.Sprintf("report_%s.html", time.Now().Format("20060102_150405"))
	}
	f, err := os.OpenFile(outPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return fmt.Errorf("创建输出文件失败: %w", err)
	}
	defer f.Close()
	view := report.View{Report: rpt, RangeLabel: report.RangeLabel("", "", "")}
	if since > 0 {
		view.RangeLabel = report.RangeLabel(since.String(), "", "")
	} else if from != "" || to != "" {
		view.RangeLabel = report.RangeLabel("", from, to)
	}
	if err := report.Render(f, view); err != nil {
		return fmt.Errorf("渲染报表失败: %w", err)
	}
	fmt.Printf("报表已生成：%s（连接 %d，认证尝试 %d，告警 %d）\n",
		outPath, rpt.TotalConnections, rpt.TotalAuthAttempts, rpt.TotalAlerts())
	return nil
}

func parseDate(s string) (time.Time, error) {
	for _, layout := range dateLayouts {
		if t, err := time.ParseInLocation(layout, s, time.Local); err == nil {
			return t, nil
		}
	}
	return time.Time{}, fmt.Errorf("无法解析时间 %q，支持 2006-01-02 或完整时间戳", s)
}
