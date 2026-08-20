package tty

import (
	"encoding/binary"
	"io"
	"sync"
	"time"
)

// maxRecordingBytes 单会话 ttyrec 录制上限：防长时间会话 + 持续输出把磁盘写爆。
// 达到上限后静默丢弃后续帧（录制截断），不影响会话本身。
const maxRecordingBytes = 64 << 20 // 64 MiB

// Recorder 以 ttyrec 格式录制终端会话（按键输入 + 输出字节流 + 时间戳）。
// ttyrec 帧头: [4B 秒][4B 微秒][4B 长度] 均为小端 uint32，后跟原始数据。
type Recorder struct {
	mu      sync.Mutex
	w       io.Writer
	written int64
}

// NewRecorder 创建录制器，w 为 ttyrec 目标文件
func NewRecorder(w io.Writer) *Recorder {
	return &Recorder{w: w}
}

// Record 写入一帧（输入或输出）
func (r *Recorder) Record(p []byte) {
	if r == nil || r.w == nil || len(p) == 0 {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.written >= maxRecordingBytes {
		return // 超过录制上限，静默丢弃后续帧
	}

	now := time.Now()
	var hdr [12]byte
	binary.LittleEndian.PutUint32(hdr[0:4], uint32(now.Unix()))
	binary.LittleEndian.PutUint32(hdr[4:8], uint32(now.Nanosecond()/1000))
	binary.LittleEndian.PutUint32(hdr[8:12], uint32(len(p)))
	_, _ = r.w.Write(hdr[:])
	_, _ = r.w.Write(p)
	r.written += int64(12 + len(p))
}
