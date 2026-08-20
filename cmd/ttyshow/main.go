// ttyshow 查看 ttyrec 会话录制：解析帧头并输出可读文本（可选剥离 ANSI 控制码）。
// 用法: go run ./cmd/ttyshow [-raw] <file.ttyrec> [file2.ttyrec ...]
package main

import (
	"encoding/binary"
	"flag"
	"fmt"
	"io"
	"os"
	"time"
)

type frame struct {
	sec  uint32
	usec uint32
	data []byte
}

func readFrames(path string) ([]frame, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var frames []frame
	start := time.Time{}
	for {
		var hdr [12]byte
		if _, err := io.ReadFull(f, hdr[:]); err != nil {
			if err == io.EOF {
				break
			}
			return nil, fmt.Errorf("read header: %w", err)
		}
		sec := binary.LittleEndian.Uint32(hdr[0:4])
		usec := binary.LittleEndian.Uint32(hdr[4:8])
		ln := binary.LittleEndian.Uint32(hdr[8:12])
		if ln > 1<<20 {
			return nil, fmt.Errorf("frame too large (%d bytes), corrupt file?", ln)
		}
		data := make([]byte, ln)
		if _, err := io.ReadFull(f, data); err != nil {
			return nil, fmt.Errorf("read frame data: %w", err)
		}
		if start.IsZero() {
			start = time.Unix(int64(sec), int64(usec)*1000)
		}
		frames = append(frames, frame{sec: sec, usec: usec, data: data})
	}
	return frames, nil
}

// stripANSI 移除 ANSI 转义序列（ESC[...m 等），保留可读字符
func stripANSI(b []byte) []byte {
	out := make([]byte, 0, len(b))
	for i := 0; i < len(b); i++ {
		if b[i] == 0x1b { // ESC
			// ESC[... <final> 或 ESC <single char>
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
		// 去掉裸 CR 以保持行对齐
		if b[i] == '\r' {
			continue
		}
		out = append(out, b[i])
	}
	return out
}

func main() {
	raw := flag.Bool("raw", false, "保留 ANSI 控制码原样输出")
	flag.Parse()
	paths := flag.Args()
	if len(paths) == 0 {
		fmt.Fprintln(os.Stderr, "usage: ttyshow [-raw] <file.ttyrec> [...]")
		os.Exit(1)
	}

	for _, p := range paths {
		frames, err := readFrames(p)
		if err != nil {
			fmt.Fprintf(os.Stderr, "%s: %v\n", p, err)
			os.Exit(1)
		}
		fmt.Printf("===== %s (%d frames) =====\n", p, len(frames))
		if len(frames) == 0 {
			continue
		}
		start := time.Unix(int64(frames[0].sec), int64(frames[0].usec)*1000)
		for _, fr := range frames {
			ts := time.Unix(int64(fr.sec), int64(fr.usec)*1000)
			body := fr.data
			if !*raw {
				body = stripANSI(body)
			}
			fmt.Printf("[%10s] %s\n", ts.Sub(start).Round(time.Millisecond).String(), string(body))
		}
	}
}
