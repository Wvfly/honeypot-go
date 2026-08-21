package vfs

import (
	"strings"
	"testing"

	"honeypot-go/internal/config"
)

func newTestFS(t *testing.T) *FileSystem {
	t.Helper()
	fs := New(config.VFSConfig{
		Hostname: "ubuntu-web-01",
		Users:    []string{"root", "ubuntu"},
	})
	return fs
}

// 节点数预算：超限后创建被拒绝
func TestNodeBudgetExhausted(t *testing.T) {
	fs := newTestFS(t)
	// 先把节点数顶到上限
	fs.mu.Lock()
	fs.totalNodes = maxTotalNodes
	fs.mu.Unlock()

	if err := fs.Mkdir("/tmp/blocked", "drwxr-xr-x", "root", "root"); err == nil {
		t.Fatal("expected Mkdir to fail when node budget exhausted")
	}
	if err := fs.WriteFile("/tmp/blocked", []byte("x")); err == nil {
		t.Fatal("expected WriteFile to fail when node budget exhausted")
	}
	// 释放一个节点后应可恢复创建
	fs.mu.Lock()
	fs.totalNodes--
	fs.mu.Unlock()
	if err := fs.Mkdir("/tmp/ok", "drwxr-xr-x", "root", "root"); err != nil {
		t.Fatalf("Mkdir should succeed after freeing budget: %v", err)
	}
}

// 字节数预算：写入超限被拒绝
func TestByteBudgetExhausted(t *testing.T) {
	fs := newTestFS(t)
	fs.mu.Lock()
	fs.totalBytes = maxTotalBytes - 4 // 剩 4 字节
	fs.mu.Unlock()

	err := fs.WriteFile("/tmp/big", []byte("12345"))
	if err == nil || !strings.Contains(err.Error(), "capacity") {
		t.Fatalf("expected capacity error, got: %v", err)
	}
	// 恰好等于剩余预算应成功
	if err := fs.WriteFile("/tmp/ok", []byte("1234")); err != nil {
		t.Fatalf("write within budget should succeed: %v", err)
	}
}

// 删除后预算回收：Remove/RemoveAll 正确回退计数
func TestBudgetReclaimedOnDelete(t *testing.T) {
	fs := newTestFS(t)
	beforeNodes, beforeBytes := fs.totalNodes, fs.totalBytes
	if err := fs.Mkdir("/tmp/d1", "drwxr-xr-x", "root", "root"); err != nil {
		t.Fatal(err)
	}
	if err := fs.WriteFile("/tmp/d1/a.txt", []byte("hello")); err != nil {
		t.Fatal(err)
	}
	if err := fs.WriteFile("/tmp/d1/b.txt", []byte("world!!!")); err != nil {
		t.Fatal(err)
	}
	if fs.totalNodes <= beforeNodes || fs.totalBytes <= beforeBytes {
		t.Fatal("creating nodes should increase budget counters")
	}
	if err := fs.RemoveAll("/tmp/d1"); err != nil {
		t.Fatal(err)
	}
	if fs.totalNodes != beforeNodes || fs.totalBytes != beforeBytes {
		t.Fatalf("budget not reclaimed after RemoveAll: nodes=%d bytes=%d, want %d/%d",
			fs.totalNodes, fs.totalBytes, beforeNodes, beforeBytes)
	}
}

// Copy 复制文件后字节/节点预算正确增长
func TestBudgetOnCopy(t *testing.T) {
	fs := newTestFS(t)
	if err := fs.WriteFile("/tmp/src.txt", []byte("0123456789")); err != nil {
		t.Fatal(err)
	}
	before := fs.totalBytes
	if err := fs.Copy("/tmp/src.txt", "/tmp/dst.txt"); err != nil {
		t.Fatal(err)
	}
	if fs.totalBytes != before+10 {
		t.Fatalf("Copy should add src size to byte budget: got %d want %d", fs.totalBytes, before+10)
	}
}
