package report

import (
	_ "embed"
	"fmt"
	"html/template"
	"io"
	"time"
)

//go:embed template.html.tmpl
var templateSource string

// severityLevels 展示顺序：越严重越靠前
var severityLevels = []string{"critical", "high", "medium", "low"}

// quickRanges 看板顶部的快捷时间范围链接（?since= 值 → 显示名）
var quickRanges = []struct{ Since, Label string }{
	{"24h", "24 小时"},
	{"168h", "7 天"},
	{"720h", "30 天"},
	{"", "全部"},
}

var tmpl = template.Must(template.New("report").Funcs(template.FuncMap{
	"pct":           formatPercent,
	"severityOrder": func() []string { return severityLevels },
	"quickRanges":   func() []struct{ Since, Label string } { return quickRanges },
	"shortID":       shortID,
	"bars":          renderBars,
	"daybars":       renderDayBars,
}).Parse(templateSource))

// View 是模板的根数据：报表本体 + 看板 HTTP 服务注入的展示参数
type View struct {
	Report
	// RefreshSec >0 时页面按该秒数自动刷新（<meta http-equiv="refresh">），0 表示不自动刷新
	RefreshSec int
	// Since/TopN 回显当前生效的查询参数，用于高亮快捷范围链接、拼切换链接
	Since string
	TopN  int
	// RangeLabel 当前统计范围的中文描述（由 RangeLabel 函数生成），展示在工具栏
	RangeLabel string
}

// Render 把报表渲染成一个自包含的 HTML 文档（内联 CSS，不依赖任何外部资源），写入 w。
func Render(w io.Writer, v View) error {
	return tmpl.Execute(w, v)
}

// RangeLabel 把 since/from/to 参数翻译成中文描述，供调用方填入 View.RangeLabel
func RangeLabel(since, from, to string) string {
	if since != "" {
		if d, err := time.ParseDuration(since); err == nil {
			return fmt.Sprintf("最近 %s", humanDuration(d))
		}
		return "最近 " + since
	}
	switch {
	case from != "" && to != "":
		return from + " ~ " + to
	case from != "":
		return from + " 起"
	case to != "":
		return "截至 " + to
	}
	return "全部数据"
}

func humanDuration(d time.Duration) string {
	switch {
	case d >= 24*time.Hour && d%(24*time.Hour) == 0:
		return fmt.Sprintf("%d 天", int(d/(24*time.Hour)))
	case d >= time.Hour && d%time.Hour == 0:
		return fmt.Sprintf("%d 小时", int(d/time.Hour))
	case d >= time.Minute && d%time.Minute == 0:
		return fmt.Sprintf("%d 分钟", int(d/time.Minute))
	}
	return d.String()
}

func formatPercent(f float64) string {
	return fmt.Sprintf("%.1f%%", f*100)
}

// shortID 连接 ID 太长时只显示前 8 位，和 dbquery 的展示习惯一致
func shortID(id string) string {
	if len(id) > 8 {
		return id[:8]
	}
	return id
}

// renderBars 把 Count 列表画成横向条形图（HTML 片段），条长按最大值归一化
func renderBars(counts []Count) template.HTML {
	if len(counts) == 0 {
		return ""
	}
	max := counts[0].Count
	for _, c := range counts {
		if c.Count > max {
			max = c.Count
		}
	}
	if max == 0 {
		max = 1
	}
	var b []byte
	for _, c := range counts {
		width := int(float64(c.Count) / float64(max) * 100)
		if width < 2 {
			width = 2
		}
		b = append(b, []byte(fmt.Sprintf(
			`<div class="bar-row"><div class="bar-name" title="%s">%s</div>`+
				`<div class="bar-track"><div class="bar-fill" style="width:%d%%"></div></div>`+
				`<div class="bar-count">%d</div></div>`,
			template.HTMLEscapeString(c.Name), template.HTMLEscapeString(c.Name), width, c.Count))...)
	}
	return template.HTML(b)
}

// renderDayBars 把按天计数画成一组竖向柱状图（HTML 片段），高度按最大值归一化
func renderDayBars(days []DayCount) template.HTML {
	if len(days) == 0 {
		return ""
	}
	var max int64 = 1
	for _, d := range days {
		if d.Count > max {
			max = d.Count
		}
	}
	var b []byte
	b = append(b, []byte(`<div class="daybars">`)...)
	for _, d := range days {
		h := int(float64(d.Count) / float64(max) * 100)
		if h < 3 {
			h = 3
		}
		// 只显示月-日，年份在报表标题的日期范围里已经有了，避免竖排文字太长
		label := d.Day
		if len(label) == 10 {
			label = label[5:]
		}
		b = append(b, []byte(fmt.Sprintf(
			`<div class="col" title="%s: %d"><div class="fill" style="height:%d%%"></div><div class="day-label">%s</div></div>`,
			template.HTMLEscapeString(d.Day), d.Count, h, template.HTMLEscapeString(label)))...)
	}
	b = append(b, []byte(`</div>`)...)
	return template.HTML(b)
}
