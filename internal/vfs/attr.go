package vfs

import (
	"errors"
	"fmt"
	"time"
)

// ErrNotPermitted 对应 EPERM。文本与 Linux strerror 一致，
// shell 命令把它原样拼进 "rm: cannot remove 'x': Operation not permitted" 之类的报错里。
var ErrNotPermitted = errors.New("Operation not permitted") //nolint:staticcheck // 需与系统报错文本完全一致

// attrLetters ext2/3/4 文件属性字母，顺序即 lsattr 输出的 22 个字符位（e2fsprogs 1.46）。
const attrLetters = "suSDiadAcEjItTeCxFNPVm"

// attrNames 与 attrLetters 一一对应的长名称（lsattr -l）
var attrNames = [...]string{
	"Secure_Deletion", "Undelete", "Synchronous_Updates", "Synchronous_Directory_Updates",
	"Immutable", "Append_Only", "No_Dump", "No_Atime", "Compression_Requested", "Encrypted",
	"Journaled_Data", "Indexed_directory", "No_Tailmerging", "Top_of_Directory_Hierarchies",
	"Extents", "No_COW", "DAX", "Casefold", "Inline_Data", "Project_Hierarchy", "Verity", "Dont_Compress",
}

const (
	// AttrImmutable i：不可修改/删除/重命名，连 root 也不行
	AttrImmutable uint32 = 1 << 4
	// AttrAppendOnly a：只能追加写，不能覆盖/删除/重命名
	AttrAppendOnly uint32 = 1 << 5
	// attrExtents e：ext4 上所有文件与目录默认都带，chattr 改不了它
	attrExtents uint32 = 1 << 14
)

// AttrBit 返回属性字母对应的位；字母不是合法属性时 ok=false
func AttrBit(letter byte) (bit uint32, ok bool) {
	for i := 0; i < len(attrLetters); i++ {
		if attrLetters[i] == letter {
			return 1 << uint(i), true
		}
	}
	return 0, false
}

// FormatAttrs 生成 lsattr 的 22 字符标志串，例如 "--------------e-------"
func FormatAttrs(flags uint32) string {
	b := make([]byte, len(attrLetters))
	for i := range b {
		if flags&(1<<uint(i)) != 0 {
			b[i] = attrLetters[i]
		} else {
			b[i] = '-'
		}
	}
	return string(b)
}

// AttrNames 返回 lsattr -l 用的长名称列表（无任何标志时为空）
func AttrNames(flags uint32) []string {
	var out []string
	for i, n := range attrNames {
		if flags&(1<<uint(i)) != 0 {
			out = append(out, n)
		}
	}
	return out
}

// Attrs 返回路径的属性位（含 ext4 默认的 e）
func (fs *FileSystem) Attrs(p string) (uint32, bool) {
	fs.mu.RLock()
	defer fs.mu.RUnlock()
	n, ok := fs.resolve(p)
	if !ok {
		return 0, false
	}
	return n.attrs | attrExtents, true
}

// SetAttrs 整体设置路径的属性位（e 位由文件系统维护，忽略）
func (fs *FileSystem) SetAttrs(p string, flags uint32) error {
	fs.mu.Lock()
	defer fs.mu.Unlock()
	n, ok := fs.resolve(p)
	if !ok {
		return fmt.Errorf("no such file or directory")
	}
	n.attrs = flags &^ attrExtents
	return nil
}

// immutable / protected：i 或 a 位，用于拦截修改类操作
func (n *node) immutable() bool { return n.attrs&AttrImmutable != 0 }
func (n *node) protected() bool { return n.attrs&(AttrImmutable|AttrAppendOnly) != 0 }

// subtreeProtected 子树内是否存在带 i/a 的节点（rm -rf 会因此失败）
func subtreeProtected(n *node) bool {
	if n.protected() {
		return true
	}
	for _, c := range n.children {
		if subtreeProtected(c) {
			return true
		}
	}
	return false
}

// 模拟开机时间：进程启动时假定机器已运行 7 天 3 小时 42 分。
// uptime / w / top / /proc/uptime / /proc/stat(btime) 都从这里取值，保证互相一致，
// 且随真实时间流逝同步增长。
var bootTime = time.Now().Add(-(7*24*time.Hour + 3*time.Hour + 42*time.Minute))

// BootTime 模拟的开机时刻
func BootTime() time.Time { return bootTime }

// Uptime 模拟的已运行时长
func Uptime() time.Duration { return time.Since(bootTime) }
