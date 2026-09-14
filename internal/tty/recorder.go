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

// Direction 标记一帧录制内容的来源方向。
//
// 交互 shell 循环里，攻击者的每次按键都会先被 RecordInput 记一帧原始输入，
// 随后服务端对该输入做回显/命令执行处理时产生的字节又会被 RecordOutput 记
// 一帧输出——两帧内容在“攻击者终端上会看到什么”这个意义上通常是重叠的（回显
// 就是服务端把收到的输入原样吐回终端）。真实回放（把字节流按时间戳原样灌回
// 一个终端）如果不区分方向、把两类帧都当屏幕输出播放，会出现每个字符显示
// 两次的问题。区分方向后，回放工具默认只播放 DirOutput，需要按键级取证时
// 再单独查看 DirInput。
type Direction byte

const (
	// DirOutput 服务端发往攻击者终端、真实会显示在屏幕上的内容。
	DirOutput Direction = 0
	// DirInput 攻击者发来的原始按键字节（未必等于屏幕显示内容，如方向键/Tab）。
	DirInput Direction = 1
)

// magic v2 格式文件的 4 字节起始标记，用于和不带方向标记的旧版 ttyrec 区分。
// 旧版文件的第一帧直接是 Unix 时间戳（秒），小端排列后凑成这 4 个 ASCII 字符
// 的概率为 0，可以安全地用来做格式探测；旧文件、新文件 ttyshow 都能读。
var magic = [4]byte{'H', 'T', 'R', '2'}

// Recorder 以扩展 ttyrec 格式录制终端会话（按键输入 + 输出字节流 + 时间戳 + 方向）。
// 帧头: [4B 秒][4B 微秒][4B 长度][1B 方向] 均为小端，长度/方向后跟原始数据。
// 文件以 4 字节 magic 开头，供 ttyshow 识别版本。
type Recorder struct {
	mu         sync.Mutex
	w          io.Writer
	written    int64
	wroteMagic bool
}

// NewRecorder 创建录制器，w 为 ttyrec 目标文件
func NewRecorder(w io.Writer) *Recorder {
	return &Recorder{w: w}
}

// RecordOutput 记录一帧“攻击者终端上实际会显示”的服务端输出。
func (r *Recorder) RecordOutput(p []byte) { r.record(p, DirOutput) }

// RecordInput 记录一帧攻击者原始输入字节（按键级取证用，回放时默认不播放，
// 避免和其对应的回显输出重复显示）。
func (r *Recorder) RecordInput(p []byte) { r.record(p, DirInput) }

func (r *Recorder) record(p []byte, dir Direction) {
	if r == nil || r.w == nil || len(p) == 0 {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.written >= maxRecordingBytes {
		return // 超过录制上限，静默丢弃后续帧
	}
	if !r.wroteMagic {
		_, _ = r.w.Write(magic[:])
		r.wroteMagic = true
		r.written += int64(len(magic))
	}

	now := time.Now()
	var hdr [13]byte
	binary.LittleEndian.PutUint32(hdr[0:4], uint32(now.Unix()))
	binary.LittleEndian.PutUint32(hdr[4:8], uint32(now.Nanosecond()/1000))
	binary.LittleEndian.PutUint32(hdr[8:12], uint32(len(p)))
	hdr[12] = byte(dir)
	_, _ = r.w.Write(hdr[:])
	_, _ = r.w.Write(p)
	r.written += int64(len(hdr)) + int64(len(p))
}
