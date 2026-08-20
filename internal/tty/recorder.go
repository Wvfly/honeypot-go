package tty

import (
	"encoding/binary"
	"io"
	"sync"
	"time"
)

// Recorder 以 ttyrec 格式录制终端会话（按键输入 + 输出字节流 + 时间戳）。
// ttyrec 帧头: [4B 秒][4B 微秒][4B 长度] 均为小端 uint32，后跟原始数据。
type Recorder struct {
	mu sync.Mutex
	w  io.Writer
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

	now := time.Now()
	var hdr [12]byte
	binary.LittleEndian.PutUint32(hdr[0:4], uint32(now.Unix()))
	binary.LittleEndian.PutUint32(hdr[4:8], uint32(now.Nanosecond()/1000))
	binary.LittleEndian.PutUint32(hdr[8:12], uint32(len(p)))
	_, _ = r.w.Write(hdr[:])
	_, _ = r.w.Write(p)
}
