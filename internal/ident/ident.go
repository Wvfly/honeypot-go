// Package ident 提供会话/连接 ID 生成。
package ident

import (
	"crypto/rand"
	"encoding/hex"
)

// New 生成带前缀的唯一 ID，如 conn_a1b2c3d4...
func New(prefix string) string {
	var b [8]byte
	_, _ = rand.Read(b[:])
	return prefix + "_" + hex.EncodeToString(b[:])
}
