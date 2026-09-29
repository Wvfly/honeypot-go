// Package report 从蜜罐的 SQLite 数据库聚合统计数据，生成活动报表
// （连接数、认证尝试、Top 攻击 IP、Top 用户名/密码、Top 命令、告警等），
// 供 cmd/report 的 HTTP 看板渲染展示。
//
// 只读查询 connections、auth_attempts、sessions、commands、events 五张表
// （结构见 internal/store），不修改任何数据，可与运行中的蜜罐共用同一个库文件。
package report

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"sort"
	"time"
)

// tsLayout 与 store 包写入 ts/opened_at 等字段时用的格式一致（本地时区 RFC3339Nano）。
// 同一时区下按此格式的字符串比较等价于时间先后比较，查询直接用字符串区间过滤。
const tsLayout = time.RFC3339Nano

// Options 报表的时间范围与列表长度
type Options struct {
	From time.Time `json:"from,omitempty"` // 零值表示不限下界
	To   time.Time `json:"to,omitempty"`   // 零值表示不限上界（含当前所有数据）
	TopN int       `json:"top_n"`          // 各类 Top 列表的条数，<=0 时取默认值 10
}

func (o Options) topN() int {
	if o.TopN <= 0 {
		return 10
	}
	return o.TopN
}

func (o Options) fromStr() string {
	if o.From.IsZero() {
		return "0000-01-01T00:00:00Z" // 字典序小于任何真实时间戳
	}
	return o.From.Format(tsLayout)
}

func (o Options) toStr() string {
	if o.To.IsZero() {
		return "9999-12-31T23:59:59Z" // 字典序大于任何真实时间戳
	}
	return o.To.Format(tsLayout)
}

// Count 名称/值计数条目，用于各类 Top-N 列表
type Count struct {
	Name  string `json:"name"`
	Count int64  `json:"count"`
}

// IPStat 单个来源 IP 的连接统计
type IPStat struct {
	SourceIP  string `json:"source_ip"`
	Conns     int64  `json:"conns"`
	FirstSeen string `json:"first_seen"`
	LastSeen  string `json:"last_seen"`
}

// CredStat 用户名或密码的尝试统计
type CredStat struct {
	Value     string `json:"value"`
	Attempts  int64  `json:"attempts"`
	Successes int64  `json:"successes"`
}

// DayCount 按天聚合的一个数据点
type DayCount struct {
	Day   string `json:"day"` // YYYY-MM-DD
	Count int64  `json:"count"`
}

// Alert 单条告警（从 events 表 payload 解析而来）
type Alert struct {
	Time         time.Time `json:"time"`
	ConnectionID string    `json:"connection_id"`
	SourceIP     string    `json:"source_ip"`
	RuleName     string    `json:"rule_name"`
	Severity     string    `json:"severity"`
	Score        int64     `json:"score"`
	Evidence     string    `json:"evidence"`
}

// Report 一次生成的完整报表数据
type Report struct {
	GeneratedAt time.Time `json:"generated_at"`
	Options     Options   `json:"options"`
	// DataFrom/DataTo 是范围内实际观测到的数据边界（可能比 Options 的范围窄），
	// 用于在报表标题里展示"实际覆盖到哪天"，而不是用户传入的开区间端点
	DataFrom string `json:"data_from"`
	DataTo   string `json:"data_to"`

	TotalConnections  int64            `json:"total_connections"`
	UniqueSourceIPs   int64            `json:"unique_source_ips"`
	TotalAuthAttempts int64            `json:"total_auth_attempts"`
	SuccessfulLogins  int64            `json:"successful_logins"`
	TotalSessions     int64            `json:"total_sessions"`
	TotalCommands     int64            `json:"total_commands"`
	TotalDownloads    int64            `json:"total_downloads"`
	AlertsBySeverity  map[string]int64 `json:"alerts_by_severity"` // critical/high/medium/low → 次数

	TopSourceIPs []IPStat   `json:"top_source_ips"`
	TopUsernames []CredStat `json:"top_usernames"`
	TopPasswords []CredStat `json:"top_passwords"`
	TopCommands  []Count    `json:"top_commands"`
	TopDownloads []Count    `json:"top_downloads"` // 下载 URL → 次数
	RecentAlerts []Alert    `json:"recent_alerts"` // 按时间倒序，最多 TopN 条
	TopRules     []Count    `json:"top_rules"`     // 命中最多的规则

	ConnectionsPerDay []DayCount `json:"connections_per_day"`
	AlertsPerDay      []DayCount `json:"alerts_per_day"`
}

// SuccessRate 弱口令登录成功率（0~1），无尝试记录时返回 0
func (r Report) SuccessRate() float64 {
	if r.TotalAuthAttempts == 0 {
		return 0
	}
	return float64(r.SuccessfulLogins) / float64(r.TotalAuthAttempts)
}

// TotalAlerts 告警总数（AlertsBySeverity 的各级别求和）
func (r Report) TotalAlerts() int64 {
	var n int64
	for _, c := range r.AlertsBySeverity {
		n += c
	}
	return n
}

// Generate 按 opts 指定的时间范围，从 db 聚合出一份完整报表。
// db 只读查询，可与运行中的蜜罐共用同一个数据库文件（sqlite 单写者+并发读兼容）。
func Generate(db *sql.DB, opts Options) (Report, error) {
	n := opts.topN()
	opts.TopN = n // 回填解析后的实际值：调用方可能传 0（表示"用默认值"），模板要展示真实生效的 N
	r := Report{GeneratedAt: time.Now(), Options: opts, AlertsBySeverity: map[string]int64{}}
	from, to := opts.fromStr(), opts.toStr()

	steps := []struct {
		name string
		fn   func() error
	}{
		{"data range", func() error { return r.loadDataRange(db, from, to) }},
		{"overview", func() error { return r.loadOverview(db, from, to) }},
		{"top source ips", func() error { return r.loadTopSourceIPs(db, from, to, n) }},
		{"top usernames", func() error { return r.loadTopCreds(db, from, to, n, "username", &r.TopUsernames) }},
		{"top passwords", func() error { return r.loadTopCreds(db, from, to, n, "password", &r.TopPasswords) }},
		{"top commands", func() error { return r.loadTopCommands(db, from, to, n) }},
		{"top downloads", func() error { return r.loadTopDownloads(db, from, to, n) }},
		{"alerts", func() error { return r.loadAlerts(db, from, to, n) }},
		{"connections per day", func() error {
			return r.loadDayCounts(db, from, to, "connections", "opened_at", "", &r.ConnectionsPerDay)
		}},
		{"alerts per day", func() error { return r.loadDayCounts(db, from, to, "events", "ts", "alert", &r.AlertsPerDay) }},
	}
	for _, s := range steps {
		if err := s.fn(); err != nil {
			return Report{}, fmt.Errorf("report: %s: %w", s.name, err)
		}
	}
	return r, nil
}

func (r *Report) loadDataRange(db *sql.DB, from, to string) error {
	row := db.QueryRow(
		`SELECT MIN(opened_at), MAX(opened_at) FROM connections WHERE opened_at >= ? AND opened_at < ?`, from, to)
	var min, max sql.NullString
	if err := row.Scan(&min, &max); err != nil {
		return err
	}
	r.DataFrom, r.DataTo = fmtTS(min.String), fmtTS(max.String)
	return nil
}

func (r *Report) loadOverview(db *sql.DB, from, to string) error {
	if err := db.QueryRow(
		`SELECT COUNT(*), COUNT(DISTINCT source_ip) FROM connections WHERE opened_at >= ? AND opened_at < ?`,
		from, to).Scan(&r.TotalConnections, &r.UniqueSourceIPs); err != nil {
		return err
	}
	var successes sql.NullInt64
	if err := db.QueryRow(
		`SELECT COUNT(*), SUM(success) FROM auth_attempts WHERE ts >= ? AND ts < ?`,
		from, to).Scan(&r.TotalAuthAttempts, &successes); err != nil {
		return err
	}
	r.SuccessfulLogins = successes.Int64
	if err := db.QueryRow(
		`SELECT COUNT(*) FROM sessions WHERE opened_at >= ? AND opened_at < ?`, from, to).Scan(&r.TotalSessions); err != nil {
		return err
	}
	if err := db.QueryRow(
		`SELECT COUNT(*) FROM commands WHERE ts >= ? AND ts < ?`, from, to).Scan(&r.TotalCommands); err != nil {
		return err
	}
	if err := db.QueryRow(
		`SELECT COUNT(*) FROM events WHERE type = 'network.download_attempt' AND ts >= ? AND ts < ?`,
		from, to).Scan(&r.TotalDownloads); err != nil {
		return err
	}
	return nil
}

func (r *Report) loadTopSourceIPs(db *sql.DB, from, to string, n int) error {
	rows, err := db.Query(
		`SELECT source_ip, COUNT(*) AS cnt, MIN(opened_at), MAX(opened_at)
		 FROM connections
		 WHERE opened_at >= ? AND opened_at < ? AND source_ip <> ''
		 GROUP BY source_ip ORDER BY cnt DESC, source_ip LIMIT ?`, from, to, n)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var s IPStat
		var first, last string
		if err := rows.Scan(&s.SourceIP, &s.Conns, &first, &last); err != nil {
			return err
		}
		s.FirstSeen, s.LastSeen = fmtTS(first), fmtTS(last)
		r.TopSourceIPs = append(r.TopSourceIPs, s)
	}
	return rows.Err()
}

// loadTopCreds 统计 auth_attempts 里某一列（username 或 password）的出现次数与成功次数。
// column 只会传入包内写死的两个字面量，不接受外部输入，拼接是安全的。
func (r *Report) loadTopCreds(db *sql.DB, from, to string, n int, column string, dst *[]CredStat) error {
	rows, err := db.Query(
		`SELECT `+column+`, COUNT(*) AS attempts, SUM(success)
		 FROM auth_attempts
		 WHERE ts >= ? AND ts < ? AND `+column+` <> ''
		 GROUP BY `+column+` ORDER BY attempts DESC, `+column+` LIMIT ?`, from, to, n)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var c CredStat
		var successes sql.NullInt64
		if err := rows.Scan(&c.Value, &c.Attempts, &successes); err != nil {
			return err
		}
		c.Successes = successes.Int64
		*dst = append(*dst, c)
	}
	return rows.Err()
}

func (r *Report) loadTopCommands(db *sql.DB, from, to string, n int) error {
	rows, err := db.Query(
		`SELECT TRIM(command) AS cmd, COUNT(*) AS cnt
		 FROM commands
		 WHERE ts >= ? AND ts < ? AND TRIM(command) <> ''
		 GROUP BY cmd ORDER BY cnt DESC, cmd LIMIT ?`, from, to, n)
	if err != nil {
		return err
	}
	defer rows.Close()
	return scanCounts(rows, &r.TopCommands)
}

// loadTopDownloads 下载 URL 的命中次数，从 events 表按类型过滤后在 Go 里解析 payload JSON。
// events.payload 不建 JSON 索引，量级对蜜罐数据完全够用，不必依赖 sqlite JSON1 扩展。
func (r *Report) loadTopDownloads(db *sql.DB, from, to string, n int) error {
	rows, err := db.Query(
		`SELECT payload FROM events WHERE type = 'network.download_attempt' AND ts >= ? AND ts < ?`, from, to)
	if err != nil {
		return err
	}
	defer rows.Close()
	counts := map[string]int64{}
	for rows.Next() {
		var payload string
		if err := rows.Scan(&payload); err != nil {
			return err
		}
		var m map[string]any
		if json.Unmarshal([]byte(payload), &m) == nil {
			if u, _ := m["url"].(string); u != "" {
				counts[u]++
			}
		}
	}
	if err := rows.Err(); err != nil {
		return err
	}
	r.TopDownloads = topNCounts(counts, n)
	return nil
}

// loadAlerts 加载告警事件，解析 payload 得到规则/级别/评分，同时填充
// AlertsBySeverity、TopRules、RecentAlerts（按时间倒序取前 n 条）。
func (r *Report) loadAlerts(db *sql.DB, from, to string, n int) error {
	rows, err := db.Query(
		`SELECT ts, payload FROM events WHERE type = 'alert' AND ts >= ? AND ts < ? ORDER BY ts`, from, to)
	if err != nil {
		return err
	}
	defer rows.Close()

	ruleCounts := map[string]int64{}
	var all []Alert
	for rows.Next() {
		var ts, payload string
		if err := rows.Scan(&ts, &payload); err != nil {
			return err
		}
		var m map[string]any
		if json.Unmarshal([]byte(payload), &m) != nil {
			continue
		}
		a := Alert{
			ConnectionID: strField(m, "connection_id"),
			SourceIP:     strField(m, "source_ip"),
			RuleName:     strField(m, "rule_name"),
			Severity:     strField(m, "severity"),
			Score:        int64Field(m, "score"),
			Evidence:     strField(m, "evidence"),
		}
		a.Time, _ = time.Parse(tsLayout, ts)
		if a.Severity == "" {
			a.Severity = "low"
		}
		r.AlertsBySeverity[a.Severity]++
		if a.RuleName != "" {
			ruleCounts[a.RuleName]++
		}
		all = append(all, a)
	}
	if err := rows.Err(); err != nil {
		return err
	}
	r.TopRules = topNCounts(ruleCounts, n)
	// 已按 ts 升序取出，倒转后取前 n 条即为"最近"的告警
	for i, j := 0, len(all)-1; i < j; i, j = i+1, j-1 {
		all[i], all[j] = all[j], all[i]
	}
	if len(all) > n {
		all = all[:n]
	}
	r.RecentAlerts = all
	return nil
}

// loadDayCounts 按天聚合某张表的行数（可选按 typeFilter 过滤 type 列，events 表用）。
// dst 传入 *[]DayCount 的地址，兼容 ConnectionsPerDay / AlertsPerDay 两个字段。
func (r *Report) loadDayCounts(db *sql.DB, from, to, table, tsCol, typeFilter string, dst *[]DayCount) error {
	query := `SELECT substr(` + tsCol + `, 1, 10) AS day, COUNT(*) FROM ` + table + ` WHERE ` + tsCol + ` >= ? AND ` + tsCol + ` < ?`
	args := []any{from, to}
	if typeFilter != "" {
		query += ` AND type = ?`
		args = append(args, typeFilter)
	}
	query += ` GROUP BY day ORDER BY day`
	rows, err := db.Query(query, args...)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var d DayCount
		if err := rows.Scan(&d.Day, &d.Count); err != nil {
			return err
		}
		*dst = append(*dst, d)
	}
	return rows.Err()
}

func scanCounts(rows *sql.Rows, dst *[]Count) error {
	for rows.Next() {
		var c Count
		if err := rows.Scan(&c.Name, &c.Count); err != nil {
			return err
		}
		*dst = append(*dst, c)
	}
	return rows.Err()
}

func topNCounts(m map[string]int64, n int) []Count {
	out := make([]Count, 0, len(m))
	for k, v := range m {
		out = append(out, Count{Name: k, Count: v})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Count != out[j].Count {
			return out[i].Count > out[j].Count
		}
		return out[i].Name < out[j].Name // 计数相同按名称稳定排序，输出可复现
	})
	if len(out) > n {
		out = out[:n]
	}
	return out
}

func strField(m map[string]any, key string) string {
	s, _ := m[key].(string)
	return s
}

func int64Field(m map[string]any, key string) int64 {
	switch v := m[key].(type) {
	case float64:
		return int64(v)
	case int64:
		return v
	}
	return 0
}

// fmtTS 把存储用的 RFC3339Nano 字符串转成报表展示用的 "2006-01-02 15:04"；解析失败原样返回
func fmtTS(s string) string {
	if s == "" {
		return ""
	}
	t, err := time.Parse(tsLayout, s)
	if err != nil {
		return s
	}
	return t.Format("2006-01-02 15:04")
}
