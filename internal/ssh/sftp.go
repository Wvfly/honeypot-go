package sshsrv

import (
	"bytes"
	"io"
	"os"
	"time"

	"github.com/pkg/sftp"

	"honeypot-go/internal/event"
	"honeypot-go/internal/vfs"
)

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

// sftpWriter 捕获上传内容：按偏移累积，写入 VFS 并发布事件
type sftpWriter struct {
	h    *vfsHandler
	path string
	buf  []byte
}

func (w *sftpWriter) WriteAt(p []byte, off int64) (int, error) {
	end := int(off) + len(p)
	if end > len(w.buf) {
		w.buf = append(w.buf, make([]byte, end-len(w.buf))...)
	}
	copy(w.buf[off:], p)
	_ = w.h.fs.WriteFile(w.path, w.buf)
	w.h.bus.Publish(event.New(event.TypeFileWritten, map[string]any{
		"session_id": w.h.sessionID,
		"path":       w.path,
		"size":       len(w.buf),
		"source":     "sftp",
	}))
	return len(p), nil
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
