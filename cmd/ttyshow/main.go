// ttyshow 查看 ttyrec 会话录制。
//
// 三种模式：
//   - replay（默认）：按原始时间间隔把字节流灌回当前终端，真实重现攻击者
//     看到的画面（含颜色、光标移动等 ANSI 效果），可用 -speed 加速。
//   - log：按帧输出「时间戳 + 方向 + 内容」的可读文本，适合审计/grep。
//   - raw：不做任何处理，把选中方向的原始字节写到 stdout，供接给其他工具。
//
// 用法:
//
//	go run ./cmd/ttyshow [flags] <file.ttyrec> [file2.ttyrec ...]
package main

import (
	"bytes"
	"encoding/binary"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// direction 帧方向；dirUnknown 用于旧版（无方向标记）录制文件。
type direction int

const (
	dirUnknown direction = iota
	dirOutput
	dirInput
)

func (d direction) label() string {
	switch d {
	case dirOutput:
		return "OUT"
	case dirInput:
		return "IN "
	default:
		return "?? "
	}
}

// filterMode -only 参数解析后的取值，与 direction 分开是为了干净地表达“全部”。
type filterMode int

const (
	filterAll filterMode = iota
	filterOutput
	filterInput
)

type frame struct {
	sec  uint32
	usec uint32
	dir  direction
	data []byte
}

func (f frame) time() time.Time {
	return time.Unix(int64(f.sec), int64(f.usec)*1000)
}

// magic 必须与 internal/tty.Recorder 使用的完全一致，用于识别 v2（带方向标记）格式。
var magic = [4]byte{'H', 'T', 'R', '2'}

// maxFrameLen 单帧长度上限：防止损坏/被篡改的文件把长度字段读成天文数字导致 OOM。
const maxFrameLen = 8 << 20 // 8 MiB，与服务端单帧输出量级一致

// readFrames 读取一个 ttyrec 文件，自动识别新旧格式。
// 第二个返回值表示该文件是否带有方向标记（v2 格式）。
func readFrames(path string) ([]frame, bool, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, false, err
	}

	hasDir := len(raw) >= 4 && bytes.Equal(raw[:4], magic[:])
	off := 0
	headerLen := 12
	if hasDir {
		off = 4
		headerLen = 13
	}

	var frames []frame
	for off < len(raw) {
		if off+headerLen > len(raw) {
			return nil, hasDir, fmt.Errorf("read header: unexpected EOF（文件可能被截断）")
		}
		hdr := raw[off : off+headerLen]
		sec := binary.LittleEndian.Uint32(hdr[0:4])
		usec := binary.LittleEndian.Uint32(hdr[4:8])
		ln := binary.LittleEndian.Uint32(hdr[8:12])
		if ln > maxFrameLen {
			return nil, hasDir, fmt.Errorf("frame too large (%d bytes), corrupt file?", ln)
		}
		dir := dirUnknown
		if hasDir && hdr[12] == 1 {
			dir = dirInput
		} else if hasDir {
			dir = dirOutput
		}
		off += headerLen
		if off+int(ln) > len(raw) {
			return nil, hasDir, fmt.Errorf("read frame data: unexpected EOF（文件可能被截断）")
		}
		data := raw[off : off+int(ln)]
		off += int(ln)
		frames = append(frames, frame{sec: sec, usec: usec, dir: dir, data: data})
	}
	return frames, hasDir, nil
}

// stripANSI 移除 ANSI 转义序列（ESC[...m 等），保留可读字符。
// 仅用于 log 模式的可读输出；replay/raw 模式必须保留原始字节，否则光标移动、
// 颜色等效果全部丢失，画面无法正确重建。
func stripANSI(b []byte) []byte {
	out := make([]byte, 0, len(b))
	for i := 0; i < len(b); i++ {
		if b[i] == 0x1b { // ESC
			if i+1 < len(b) && b[i+1] == '[' {
				i += 2
				for i < len(b) && !(b[i] >= 0x40 && b[i] <= 0x7e) {
					i++
				}
			} else if i+1 < len(b) {
				i++
			}
			continue
		}
		if b[i] == '\r' {
			continue
		}
		out = append(out, b[i])
	}
	return out
}

// ---- 输出配色（仅用于我们自己打印的时间戳/方向标签/横幅，不影响回放内容本身） ----

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
	ansiReset  = "\x1b[0m"
	ansiDim    = "\x1b[2m"
	ansiGray   = "\x1b[90m"
	ansiCyan   = "\x1b[36m"
	ansiYellow = "\x1b[33m"
	ansiBold   = "\x1b[1m"
)

func paint(code, s string) string {
	if !colorEnabled {
		return s
	}
	return code + s + ansiReset
}

func main() {
	mode := flag.String("mode", "replay", `显示模式: replay(实时回放,默认) | log(逐帧文本日志) | raw(原始字节直通)`)
	speed := flag.Float64("speed", 1.0, "replay 模式回放速度倍数，2 表示 2 倍速；0 表示不等待、瞬间输出全部内容")
	maxGap := flag.Duration("max-gap", 2*time.Second, "replay 模式单次等待的上限（真实停顿可能长达数分钟，超过此值按此值等待，避免陪跑）")
	only := flag.String("only", "", `只显示指定方向的帧: output | input | all；不填时，v2 格式（有方向标记）默认只放 output（避免按键回显重复显示一次），旧版无标记文件默认 all`)
	ansiFlag := flag.Bool("ansi", false, "log 模式下保留原始 ANSI 控制码（默认剥离，便于阅读/grep）")
	noColor := flag.Bool("no-color", false, "禁用时间戳/方向标签等自带的颜色（不影响回放内容本身的颜色）")
	flag.Parse()
	paths := flag.Args()
	if len(paths) == 0 {
		fmt.Fprintln(os.Stderr, "用法: ttyshow [-mode replay|log|raw] [-speed N] [-only output|input|all] <file.ttyrec> [...]")
		os.Exit(1)
	}
	if *noColor {
		colorEnabled = false
	}

	for i, p := range paths {
		if i > 0 {
			fmt.Println()
		}
		if err := showOne(p, *mode, *speed, *maxGap, *only, *ansiFlag); err != nil {
			fmt.Fprintf(os.Stderr, "%s: %v\n", p, err)
			os.Exit(1)
		}
	}
}

func showOne(path, mode string, speed float64, maxGap time.Duration, only string, keepANSI bool) error {
	frames, hasDir, err := readFrames(path)
	if err != nil {
		return err
	}

	want, explicit := resolveOnly(only, hasDir)
	if explicit && !hasDir && want != filterAll {
		fmt.Fprintf(os.Stderr, "warn: %s 是旧版录制（无方向标记），无法按方向筛选，已按 all 显示\n", filepath.Base(path))
		want = filterAll
	}

	filtered := make([]frame, 0, len(frames))
	for _, f := range frames {
		switch want {
		case filterOutput:
			if f.dir == dirOutput {
				filtered = append(filtered, f)
			}
		case filterInput:
			if f.dir == dirInput {
				filtered = append(filtered, f)
			}
		default: // filterAll
			filtered = append(filtered, f)
		}
	}

	dur := time.Duration(0)
	if len(frames) > 0 {
		dur = frames[len(frames)-1].time().Sub(frames[0].time())
	}
	header := fmt.Sprintf("===== %s (%d 帧, %s", filepath.Base(path), len(frames), dur.Round(time.Millisecond))
	if hasDir {
		header += ", 含方向标记"
	} else {
		header += ", 旧版录制/无方向标记"
	}
	header += ") ====="
	fmt.Println(paint(ansiBold, header))
	if len(filtered) == 0 {
		fmt.Println(paint(ansiDim, "(没有符合筛选条件的帧)"))
		return nil
	}

	switch mode {
	case "replay":
		return replay(filtered, speed, maxGap)
	case "log":
		printLog(filtered, keepANSI)
		return nil
	case "raw":
		for _, f := range filtered {
			_, _ = os.Stdout.Write(f.data)
		}
		return nil
	default:
		return fmt.Errorf("未知 -mode %q，可选 replay|log|raw", mode)
	}
}

// resolveOnly 解析 -only 参数。explicit 表示用户是否显式传了该参数
// （区分"用户没传，走默认策略" 与 "用户传了 output/input/all"）。
func resolveOnly(only string, hasDir bool) (mode filterMode, explicit bool) {
	switch only {
	case "output":
		return filterOutput, true
	case "input":
		return filterInput, true
	case "all":
		return filterAll, true
	case "":
		if hasDir {
			// 默认只放服务端输出：攻击者按键的回显已经体现在输出帧里，
			// 两者都播放会导致同一内容显示两次。
			return filterOutput, false
		}
		return filterAll, false
	default:
		fmt.Fprintf(os.Stderr, "warn: 未知 -only=%q，按 all 处理\n", only)
		return filterAll, true
	}
}

// replay 按原始帧间时间间隔把内容写到 stdout，真实重现终端画面。
func replay(frames []frame, speed float64, maxGap time.Duration) error {
	if speed < 0 {
		speed = 1
	}
	var prev time.Time
	for i, f := range frames {
		t := f.time()
		if i > 0 && speed > 0 {
			gap := t.Sub(prev)
			if gap > maxGap {
				gap = maxGap
			}
			if gap > 0 {
				time.Sleep(time.Duration(float64(gap) / speed))
			}
		}
		prev = t
		if _, err := os.Stdout.Write(f.data); err != nil {
			return err
		}
	}
	// 重置终端属性，避免上一段录制里未闭合的颜色/属性污染后续输出（多文件连播时尤其明显）。
	fmt.Print("\x1b[0m")
	return nil
}

// printLog 打印「时间戳 + 方向 + 内容」逐帧文本，适合审计/grep，默认剥离 ANSI 控制码。
func printLog(frames []frame, keepANSI bool) {
	start := frames[0].time()
	for _, f := range frames {
		ts := f.time().Sub(start).Round(time.Millisecond)
		body := f.data
		if !keepANSI {
			body = stripANSI(body)
		}
		label := f.dir.label()
		labelColor := ansiCyan
		if f.dir == dirInput {
			labelColor = ansiYellow
		}
		fmt.Printf("%s %s %s\n",
			paint(ansiGray, fmt.Sprintf("[%10s]", ts.String())),
			paint(labelColor, label),
			string(body))
	}
}
