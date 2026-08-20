package sshsrv

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"sync"
	"time"

	"github.com/pkg/sftp"

	"honeypot-go/internal/event"
	"honeypot-go/internal/vfs"
)

// maxUploadSize 单文件上传大小上限：防止恶意客户端用超大偏移/超大写入
// 触发 make 分配任意大小内存导致 OOM（32 位平台上 int 溢出还会直接 panic）。
const maxUploadSize = 64 << 20 // 64 MiB

// sftpFlushStep sftp 上传落盘/事件节流步长：buf 相对上次写回增长达该阈值才全量
// 写回 VFS 并发布一次 file.written 事件。此前每次 WriteAt 都全量复制 + 发事件，
// 恶意客户端用海量小写入（如 1 字节 × 数十万次）可把内存拷贝放大到几十 GB 并
// 用事件淹没检测/存储链路；节流后两者都降到「每步长一次 + 文件关闭一次」。
const sftpFlushStep = 4 << 20 // 4 MiB

// vfsHandler 把虚拟文件系统适配为 pkg/sftp 服务端处理器：
// 读/列目录走 VFS；写操作捕获攻击者上传内容（落 VFS + 发 file.written 事件）。
type vfsHandler struct {
	fs        *vfs.FileSystem
	bus       *event.Bus
	sessionID string
}

func (h *vfsHandler) Fileread(r *sftp.Request) (io.ReaderAt, error) {
	data, err := h.fs.ReadFile(r.Filepath)
	if err != nil {
		return nil, os.ErrNotExist
	}
	return bytes.NewReader(data), nil
}

func (h *vfsHandler) Filewrite(r *sftp.Request) (io.WriterAt, error) {
	return &sftpWriter{h: h, path: r.Filepath}, nil
}

func (h *vfsHandler) Filecmd(r *sftp.Request) error {
	// M2 简化：mkdir/rename/remove 等假装成功，不真实变更（后续可扩展）
	return nil
}

func (h *vfsHandler) Filelist(r *sftp.Request) (sftp.ListerAt, error) {
	// pkg/sftp 下发的 Method 为驼峰：opendir→"List"、stat→"Stat"、lstat→"Lstat"
	switch r.Method {
	case "Stat", "Lstat":
		info, ok := h.fs.Resolve(r.Filepath)
		if !ok {
			return nil, os.ErrNotExist
		}
		return vfsLister{os.FileInfo(vfsFileInfo{info})}, nil
	case "List":
		infos, err := h.fs.List(r.Filepath)
		if err != nil {
			return nil, os.ErrNotExist
		}
		entries := make([]os.FileInfo, 0, len(infos))
		for _, fi := range infos {
			entries = append(entries, os.FileInfo(vfsFileInfo{fi}))
		}
		return vfsLister(entries), nil
	}
	return nil, os.ErrNotExist
}

// vfsLister 实现 sftp.ListerAt（参照官方示例）
type vfsLister []os.FileInfo

func (f vfsLister) ListAt(ls []os.FileInfo, offset int64) (int, error) {
	var n int
	if offset >= int64(len(f)) {
		return 0, io.EOF
	}
	if offset < 0 {
		offset = 0
	}
	n = copy(ls, f[offset:])
	if n < len(ls) {
		return n, io.EOF
	}
	return n, nil
}

// sftpWriter 捕获上传内容：按偏移累积到内存 buf，达到节流步长或文件关闭时
// 全量写回 VFS 并发布事件。实现 io.Closer 与 sftp.TransferError，让 pkg/sftp
// 在客户端 CLOSE（正常）与连接异常断开（兜底）时都能触发最终落盘。
//
// 并发说明：pkg/sftp 用 8 个 worker 并发执行同一 handle 的 WRITE（packet-manager.go
// 的 rwChan 无顺序保证），WriteAt 可能被多 goroutine 并发调用。buf 的扩容/拷贝、
// pubSize/dirty 读写若不互斥会竞态：轻则上传内容错乱，重则并发 append 触发
// 切片越界 panic，直接把整个蜜罐进程打崩（进程级 DoS）。故所有字段操作持锁。
type sftpWriter struct {
	mu      sync.Mutex
	h       *vfsHandler
	path    string
	buf     []byte
	pubSize int64 // 已写回 VFS 且已发布事件的 buf 长度
	dirty   bool  // buf 存在未写回内容
	closed  bool
}

func (w *sftpWriter) WriteAt(p []byte, off int64) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	// 防御：off/len 均由客户端完全控制。负偏移、超限偏移或超大写入直接拒绝，
	// 避免 make([]byte, 任意大小) 触发 OOM / 32 位 int 溢出 panic。
	if off < 0 || len(p) > maxUploadSize || off > maxUploadSize || off+int64(len(p)) > maxUploadSize {
		return 0, fmt.Errorf("sftp write exceeds limit: off=%d len=%d max=%d", off, len(p), maxUploadSize)
	}
	end := int(off) + len(p)
	if end > len(w.buf) {
		w.buf = append(w.buf, make([]byte, end-len(w.buf))...)
	}
	copy(w.buf[off:], p)
	w.dirty = true
	// 节流：仅当 buf 比上次写回增长达步长时才全量落盘 + 发布事件。
	// 未达步长的写入暂存内存，由 Close/TransferError 兜底一次性写回，
	// 把全量复制与事件数从「每次写入」降到「每步长一次」，最终一致性不受影响
	//（覆盖写/随机偏移写只要未触发本条件，也由收尾统一写回，内容不丢）。
	if int64(len(w.buf))-w.pubSize >= sftpFlushStep {
		return len(p), w.flush()
	}
	return len(p), nil
}

// flush 把当前 buf 全量写回 VFS 并发布事件（仅当存在未写回内容）。
// 调用方必须已持有 w.mu；锁序 w.mu -> fs.mu（WriteFile 内部），无反向，不会死锁。
func (w *sftpWriter) flush() error {
	if !w.dirty {
		return nil
	}
	if err := w.h.fs.WriteFile(w.path, w.buf); err != nil {
		// 写入失败（VFS 权限/大小校验拒绝），把错误返回给客户端，且不发布事件；
		// dirty 保持 true，后续写入或 Close 时会重试
		return err
	}
	w.pubSize = int64(len(w.buf))
	w.dirty = false
	w.h.bus.Publish(event.New(event.TypeFileWritten, map[string]any{
		"session_id": w.h.sessionID,
		"path":       w.path,
		"size":       len(w.buf),
		"source":     "sftp",
	}))
	return nil
}

// Close 实现 io.Closer：pkg/sftp 在客户端发送 CLOSE 请求时调用（此前已
// working.Wait() 等全部 WRITE 完成，不会与 WriteAt 并发，加锁仅为防御）。
// 小文件上传（未达节流步长）的最终状态在此落盘并发布事件，保证检测不漏报。
func (w *sftpWriter) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.closed {
		return nil
	}
	w.closed = true
	return w.flush()
}

// TransferError 实现 sftp.TransferError：连接异常断开（客户端崩溃/断网）时由
// pkg/sftp 调用（此时连接已断、无新 WRITE 到达），尽力写回已上传内容，避免
// 数据丢失与检测事件遗漏。错误无处可传，仅忽略落盘错误（内存 VFS 中失败概率极低）。
func (w *sftpWriter) TransferError(err error) {
	if err == nil {
		return
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	_ = w.flush()
}

// vfsFileInfo 把 vfs.FileInfo 适配为 os.FileInfo（sftp 列表所需）
type vfsFileInfo struct {
	vfs.FileInfo
}

func (f vfsFileInfo) Name() string       { return f.FileInfo.Name }
func (f vfsFileInfo) Size() int64        { return f.FileInfo.Size }
func (f vfsFileInfo) ModTime() time.Time { return time.Time{} }
func (f vfsFileInfo) IsDir() bool        { return f.FileInfo.IsDir }
func (f vfsFileInfo) Sys() any           { return nil }

func (f vfsFileInfo) Mode() os.FileMode {
	if f.FileInfo.IsDir {
		return os.ModeDir | 0o755
	}
	return 0o644
}
