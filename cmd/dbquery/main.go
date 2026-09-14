// dbquery 蜜罐攻击记录查询工具：把 5 张表按“连接”关联展示成可读的攻击报告，
// 而不是分表原样倾倒。用于运营核查/事后分析。
//
// 用法:
//
//	go run ./cmd/dbquery [flags]
package main

import (
	"database/sql"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	_ "modernc.org/sqlite"
)

// ---- 数据模型（与 internal/store 的建表语句一一对应） ----

type connRow struct {
	id, openedAt, closedAt, sourceIP, clientVersion string
	sourcePort, targetPort                          int64
}

type authRow struct {
	connID, ts, username, password, method string
	success                                bool
	delayMS                                int64
}

type sessionRow struct {
	id, connID, channelType, term, openedAt, closedAt string
	cols, rows                                        int64
}

type commandRow struct {
	sessionID, ts, command, cwd, outputPreview string
	exitCode, durationMS                       int64
}

// eventRow 对应通用 events 表：download/connect/file/alert 等 M2 扩展事件。
type eventRow struct {
	typ, ts, connID, sessionID, payload string
}

// ---- 聚合后的报告结构 ----

type report struct {
	conn        connRow
	auths       []authRow
	sessions    []*sessionReport
	connEvents  []eventRow // 直接挂在 connection_id 下的事件（目前主要是 alert）
	maxSeverity string     // 该连接下出现过的最高告警级别，用于整行着色
	maxScore    int64
}

type sessionReport struct {
	sess       sessionRow
	commands   []commandRow
	events     []eventRow // file.written / network.* 等挂在 session_id 下的事件
	recordPath string     // 若对应 ttyrec 录制文件存在，则为其路径
}

func main() {
	dbPath := flag.String("db", "data/honeypot.db", "sqlite 数据库路径")
	recDir := flag.String("recordings", "", "ttyrec 录制目录（默认取 <db 所在目录>/recordings）")
	ipFilter := flag.String("ip", "", "只看来源 IP 包含该子串的连接")
	connFilter := flag.String("conn", "", "只看指定 connection_id（支持前缀匹配）")
	since := flag.Duration("since", 0, "只看最近这段时间内建立的连接，如 -since 24h（0 表示不限制）")
	alertsOnly := flag.Bool("alerts-only", false, "只显示触发过告警的连接")
	limit := flag.Int("limit", 50, "最多显示多少个连接（按建立时间倒序），0 表示不限")
	full := flag.Bool("full", false, "认证尝试全部展开显示，不做折叠省略")
	noColor := flag.Bool("no-color", false, "禁用彩色输出")
	flag.Parse()

	if *recDir == "" {
		*recDir = filepath.Join(filepath.Dir(*dbPath), "recordings")
	}
	if *noColor {
		colorEnabled = false
	}

	db, err := sql.Open("sqlite", *dbPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "open db:", err)
		os.Exit(1)
	}
	defer db.Close()

	conns, err := loadConnections(db)
	if err != nil {
		fmt.Fprintln(os.Stderr, "query connections:", err)
		os.Exit(1)
	}
	auths, err := loadAuths(db)
	if err != nil {
		fmt.Fprintln(os.Stderr, "query auth_attempts:", err)
		os.Exit(1)
	}
	sessions, err := loadSessions(db)
	if err != nil {
		fmt.Fprintln(os.Stderr, "query sessions:", err)
		os.Exit(1)
	}
	commands, err := loadCommands(db)
	if err != nil {
		fmt.Fprintln(os.Stderr, "query commands:", err)
		os.Exit(1)
	}
	events, err := loadEvents(db)
	if err != nil {
		fmt.Fprintln(os.Stderr, "query events:", err)
		os.Exit(1)
	}

	reports, sessionToConn := buildReports(conns, auths, sessions, commands, events, *recDir)

	// 过滤 + 排序（按建立时间倒序，最新的攻击排前面）
	filtered := make([]*report, 0, len(reports))
	sinceCut := time.Time{}
	if *since > 0 {
		sinceCut = time.Now().Add(-*since)
	}
	for _, r := range reports {
		if *ipFilter != "" && !strings.Contains(r.conn.sourceIP, *ipFilter) {
			continue
		}
		if *connFilter != "" && !strings.HasPrefix(r.conn.id, *connFilter) {
			continue
		}
		if *alertsOnly && r.maxSeverity == "" {
			continue
		}
		if !sinceCut.IsZero() {
			t, err := time.Parse(time.RFC3339Nano, r.conn.openedAt)
			if err == nil && t.Before(sinceCut) {
				continue
			}
		}
		filtered = append(filtered, r)
	}
	sort.Slice(filtered, func(i, j int) bool {
		return filtered[i].conn.openedAt > filtered[j].conn.openedAt
	})

	printSummary(reports, auths)

	shown := filtered
	if *limit > 0 && len(shown) > *limit {
		shown = shown[:*limit]
	}
	if len(reports) > 0 {
		fmt.Println()
		fmt.Println(paint(ansiBold, fmt.Sprintf("== 连接详情（%d/%d，按最新在前） ==", len(shown), len(filtered))))
	}
	_ = sessionToConn // 仅用于构建阶段的关联，展示阶段不再需要
	for _, r := range shown {
		printReport(r, *full)
	}
}

// ---- 加载 ----

func loadConnections(db *sql.DB) ([]connRow, error) {
	rows, err := db.Query(`SELECT id, opened_at, COALESCE(closed_at,''), source_ip, source_port, target_port, client_version FROM connections`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []connRow
	for rows.Next() {
		var c connRow
		if err := rows.Scan(&c.id, &c.openedAt, &c.closedAt, &c.sourceIP, &c.sourcePort, &c.targetPort, &c.clientVersion); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

func loadAuths(db *sql.DB) ([]authRow, error) {
	rows, err := db.Query(`SELECT connection_id, ts, username, password, method, success, delay_ms FROM auth_attempts ORDER BY ts`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []authRow
	for rows.Next() {
		var a authRow
		var success int64
		if err := rows.Scan(&a.connID, &a.ts, &a.username, &a.password, &a.method, &success, &a.delayMS); err != nil {
			return nil, err
		}
		a.success = success != 0
		out = append(out, a)
	}
	return out, rows.Err()
}

func loadSessions(db *sql.DB) ([]sessionRow, error) {
	rows, err := db.Query(`SELECT id, connection_id, channel_type, COALESCE(term,''), cols, rows, opened_at, COALESCE(closed_at,'') FROM sessions ORDER BY opened_at`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []sessionRow
	for rows.Next() {
		var s sessionRow
		if err := rows.Scan(&s.id, &s.connID, &s.channelType, &s.term, &s.cols, &s.rows, &s.openedAt, &s.closedAt); err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, rows.Err()
}

func loadCommands(db *sql.DB) ([]commandRow, error) {
	rows, err := db.Query(`SELECT session_id, ts, command, cwd, exit_code, duration_ms, output_preview FROM commands ORDER BY ts`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []commandRow
	for rows.Next() {
		var c commandRow
		if err := rows.Scan(&c.sessionID, &c.ts, &c.command, &c.cwd, &c.exitCode, &c.durationMS, &c.outputPreview); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

func loadEvents(db *sql.DB) ([]eventRow, error) {
	rows, err := db.Query(`SELECT type, ts, COALESCE(connection_id,''), COALESCE(session_id,''), payload FROM events ORDER BY ts`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []eventRow
	for rows.Next() {
		var e eventRow
		if err := rows.Scan(&e.typ, &e.ts, &e.connID, &e.sessionID, &e.payload); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// ---- 聚合 ----

func buildReports(conns []connRow, auths []authRow, sessions []sessionRow, commands []commandRow, events []eventRow, recDir string) (map[string]*report, map[string]string) {
	reports := make(map[string]*report, len(conns))
	for _, c := range conns {
		reports[c.id] = &report{conn: c}
	}
	// 有些连接可能因为进程异常退出没有落地 connections 行，但仍有 auth/session 记录；
	// 兜底补一行“影子连接”，避免这些数据在报告里悄悄消失。
	ensure := func(id string) *report {
		if r, ok := reports[id]; ok {
			return r
		}
		r := &report{conn: connRow{id: id}}
		reports[id] = r
		return r
	}

	for _, a := range auths {
		if a.connID == "" {
			continue
		}
		r := ensure(a.connID)
		r.auths = append(r.auths, a)
	}

	sessByID := make(map[string]*sessionReport, len(sessions))
	sessionToConn := make(map[string]string, len(sessions))
	for _, s := range sessions {
		sr := &sessionReport{sess: s}
		p := filepath.Join(recDir, s.id+".ttyrec")
		if fi, err := os.Stat(p); err == nil && !fi.IsDir() {
			sr.recordPath = p
		}
		sessByID[s.id] = sr
		sessionToConn[s.id] = s.connID
		if s.connID != "" {
			r := ensure(s.connID)
			r.sessions = append(r.sessions, sr)
		}
	}

	for _, c := range commands {
		if sr, ok := sessByID[c.sessionID]; ok {
			sr.commands = append(sr.commands, c)
		}
	}

	for _, e := range events {
		switch {
		case e.typ == "alert":
			connID := e.connID
			if connID == "" {
				connID = sessionToConn[e.sessionID]
			}
			if connID == "" {
				continue
			}
			r := ensure(connID)
			r.connEvents = append(r.connEvents, e)
			sev, score := parseAlertPayload(e.payload)
			if severityRank(sev) > severityRank(r.maxSeverity) {
				r.maxSeverity = sev
			}
			if score > r.maxScore {
				r.maxScore = score
			}
		default: // network.download_attempt / network.connect_attempt / file.written 等
			if sr, ok := sessByID[e.sessionID]; ok {
				sr.events = append(sr.events, e)
			} else if e.connID != "" {
				r := ensure(e.connID)
				r.connEvents = append(r.connEvents, e)
			}
		}
	}

	return reports, sessionToConn
}

func parseAlertPayload(payload string) (severity string, score int64) {
	var m map[string]any
	if err := json.Unmarshal([]byte(payload), &m); err != nil {
		return "", 0
	}
	if s, ok := m["severity"].(string); ok {
		severity = s
	}
	switch v := m["score"].(type) {
	case float64:
		score = int64(v)
	case string:
		if n, err := strconv.ParseInt(v, 10, 64); err == nil {
			score = n
		}
	}
	return severity, score
}

func severityRank(s string) int {
	switch s {
	case "critical":
		return 4
	case "high":
		return 3
	case "medium":
		return 2
	case "low":
		return 1
	default:
		return 0
	}
}

// ---- 配色 ----

var colorEnabled = detectColor()

func detectColor() bool {
	if os.Getenv("NO_COLOR") != "" {
		return false
	}
	fi, err := os.Stdout.Stat()
	if err != nil {
		return false
	}
	return fi.Mode()&os.ModeCharDevice != 0
}

const (
	ansiReset   = "\x1b[0m"
	ansiBold    = "\x1b[1m"
	ansiDim     = "\x1b[2m"
	ansiGray    = "\x1b[90m"
	ansiGreen   = "\x1b[32m"
	ansiYellow  = "\x1b[33m"
	ansiRed     = "\x1b[31m"
	ansiBoldRed = "\x1b[1;31m"
	ansiCyan    = "\x1b[36m"
)

func paint(code, s string) string {
	if !colorEnabled {
		return s
	}
	return code + s + ansiReset
}

func severityColor(sev string) string {
	switch sev {
	case "critical":
		return ansiBoldRed
	case "high":
		return ansiRed
	case "medium":
		return ansiYellow
	case "low":
		return ansiCyan
	default:
		return ansiDim
	}
}

// ---- 汇总统计 ----

func printSummary(reports map[string]*report, auths []authRow) {
	var (
		totalConns  = len(reports)
		totalAuth   int
		successAuth int
		ipCount     = map[string]int{}
		pwCount     = map[string]int{}
		sevCount    = map[string]int{}
	)
	for _, r := range reports {
		if r.conn.sourceIP != "" {
			ipCount[r.conn.sourceIP]++
		}
		if r.maxSeverity != "" {
			sevCount[r.maxSeverity]++
		}
	}
	for _, a := range auths {
		totalAuth++
		if a.success {
			successAuth++
		}
		if a.password != "" {
			pwCount[a.password]++
		}
	}

	fmt.Println(paint(ansiBold, "== 概览 =="))
	fmt.Printf("  连接总数: %d    认证尝试: %d（成功 %s）\n",
		totalConns, totalAuth, paint(ansiGreen, fmt.Sprintf("%d", successAuth)))
	if len(sevCount) > 0 {
		parts := make([]string, 0, 4)
		for _, sev := range []string{"critical", "high", "medium", "low"} {
			if n := sevCount[sev]; n > 0 {
				parts = append(parts, paint(severityColor(sev), fmt.Sprintf("%s×%d", sev, n)))
			}
		}
		fmt.Printf("  触发告警的连接: %s\n", strings.Join(parts, "  "))
	}
	if top := topN(ipCount, 5); len(top) > 0 {
		fmt.Println("  高频来源 IP:")
		for _, kv := range top {
			fmt.Printf("    %-20s %d 次连接\n", kv.key, kv.count)
		}
	}
	if top := topN(pwCount, 8); len(top) > 0 {
		fmt.Println("  高频尝试密码:")
		for _, kv := range top {
			fmt.Printf("    %-20s %d 次\n", kv.key, kv.count)
		}
	}
}

type kvCount struct {
	key   string
	count int
}

func topN(m map[string]int, n int) []kvCount {
	list := make([]kvCount, 0, len(m))
	for k, v := range m {
		list = append(list, kvCount{k, v})
	}
	sort.Slice(list, func(i, j int) bool {
		if list[i].count != list[j].count {
			return list[i].count > list[j].count
		}
		return list[i].key < list[j].key
	})
	if len(list) > n {
		list = list[:n]
	}
	return list
}

// ---- 单个连接的详细展示 ----

func printReport(r *report, full bool) {
	fmt.Println()
	head := fmt.Sprintf("[%s] %s:%d -> :%d", shortID(r.conn.id), orDash(r.conn.sourceIP), r.conn.sourcePort, r.conn.targetPort)
	if r.maxSeverity != "" {
		head = fmt.Sprintf("%s  %s", head, paint(severityColor(r.maxSeverity), fmt.Sprintf("[%s 风险分=%d]", r.maxSeverity, r.maxScore)))
	}
	fmt.Println(paint(ansiBold, head))
	fmt.Printf("  时间: %s -> %s   客户端: %s\n", fmtTime(r.conn.openedAt), fmtTime(r.conn.closedAt), orDash(r.conn.clientVersion))

	printAuths(r.auths, full)

	for _, sr := range r.sessions {
		printSession(sr)
	}

	for _, e := range r.connEvents {
		printEvent(e, "  ")
	}
}

func printAuths(auths []authRow, full bool) {
	if len(auths) == 0 {
		return
	}
	fails := 0
	pws := make([]string, 0, len(auths))
	seen := map[string]bool{}
	for _, a := range auths {
		if !a.success {
			fails++
		}
		if a.password != "" && !seen[a.password] {
			seen[a.password] = true
			pws = append(pws, a.password)
		}
	}
	fmt.Printf("  %s\n", paint(ansiDim, fmt.Sprintf("认证尝试 %d 次（成功 %d / 失败 %d），试过的密码: %s",
		len(auths), len(auths)-fails, fails, strings.Join(pws, ", "))))

	shown := auths
	const previewN = 5
	truncated := false
	if !full && len(shown) > previewN {
		shown = shown[:previewN]
		truncated = true
	}
	for _, a := range shown {
		line := fmt.Sprintf("    %s user=%-10s pass=%-14s method=%-20s delay=%dms",
			fmtTime(a.ts), a.username, a.password, a.method, a.delayMS)
		if a.success {
			fmt.Println(paint(ansiGreen, line+" ✓ 放行"))
		} else {
			fmt.Println(paint(ansiDim, line))
		}
	}
	if truncated {
		fmt.Printf("    %s\n", paint(ansiDim, fmt.Sprintf("... 省略 %d 条（加 -full 查看全部）", len(auths)-previewN)))
	}
}

func printSession(sr *sessionReport) {
	fmt.Printf("  %s\n", paint(ansiCyan, fmt.Sprintf("会话 [%s] %s term=%s %dx%d  %s -> %s",
		shortID(sr.sess.id), sr.sess.channelType, orDash(sr.sess.term), sr.sess.cols, sr.sess.rows,
		fmtTime(sr.sess.openedAt), fmtTime(sr.sess.closedAt))))
	if sr.recordPath != "" {
		fmt.Printf("    录制: %s（回放: go run ./cmd/ttyshow %s）\n", sr.recordPath, sr.recordPath)
	}
	for _, c := range sr.commands {
		exitStr := fmt.Sprintf("%d", c.exitCode)
		if c.exitCode != 0 {
			exitStr = paint(ansiRed, exitStr)
		}
		fmt.Printf("    %s cwd=%-20s exit=%s dur=%dms  %s\n",
			fmtTime(c.ts), c.cwd, exitStr, c.durationMS, paint(ansiBold, c.command))
		if c.outputPreview != "" {
			fmt.Printf("      %s\n", paint(ansiDim, "-> "+singleLine(c.outputPreview)))
		}
	}
	for _, e := range sr.events {
		printEvent(e, "    ")
	}
}

func printEvent(e eventRow, indent string) {
	var m map[string]any
	_ = json.Unmarshal([]byte(e.payload), &m)
	switch e.typ {
	case "alert":
		sev, _ := m["severity"].(string)
		fmt.Printf("%s%s\n", indent, paint(severityColor(sev), fmt.Sprintf("⚠ [%s] %v  分数=%v  依据=%v",
			sev, m["rule_name"], m["score"], m["evidence"])))
	case "network.download_attempt":
		fmt.Printf("%s%s\n", indent, fmt.Sprintf("↓ 下载尝试: tool=%v url=%v", m["tool"], m["url"]))
	case "network.connect_attempt":
		fmt.Printf("%s%s\n", indent, fmt.Sprintf("→ 外连尝试: tool=%v target=%v:%v", m["tool"], m["target"], m["port"]))
	case "file.written":
		fmt.Printf("%s%s\n", indent, fmt.Sprintf("📄 文件写入: path=%v size=%v source=%v", m["path"], m["size"], m["source"]))
	default:
		fmt.Printf("%s%s %s\n", indent, e.typ, e.payload)
	}
}

// ---- 小工具函数 ----

func shortID(id string) string {
	if len(id) <= 12 {
		return id
	}
	return id[:12]
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

func fmtTime(s string) string {
	if s == "" {
		return "-"
	}
	t, err := time.Parse(time.RFC3339Nano, s)
	if err != nil {
		return s
	}
	return t.Local().Format("01-02 15:04:05")
}

func singleLine(s string) string {
	s = strings.ReplaceAll(s, "\r\n", " ")
	s = strings.ReplaceAll(s, "\n", " ")
	if len(s) > 120 {
		s = s[:120] + "..."
	}
	return s
}
