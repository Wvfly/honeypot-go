package vfs

import (
	"fmt"
	fsys "io/fs"
	"path"
	"sort"
	"strings"
	"sync"
	"time"

	"honeypot-go/internal/config"
)

// node 虚拟文件系统节点
type node struct {
	name     string
	isDir    bool
	perm     string // 类似 "-rw-r--r--" 的权限串
	owner    string
	group    string
	size     int64
	mtime    time.Time
	content  []byte
	children map[string]*node
}

// FileSystem 内存虚拟文件系统（M1：只读快照 + 基本目录导航）
type FileSystem struct {
	mu       sync.RWMutex
	root     *node
	hostname string
}

// New 创建并预置一个逼真的 Linux 根文件系统
func New(cfg config.VFSConfig) *FileSystem {
	fs := &FileSystem{
		hostname: cfg.Hostname,
		root:     &node{name: "/", isDir: true, perm: "drwxr-xr-x", owner: "root", group: "root", children: map[string]*node{}},
	}
	fs.bootstrap(cfg.Users)
	return fs
}

func (fs *FileSystem) addFile(path, perm, owner, group string, content []byte) {
	parts := splitPath(path)
	dir := fs.root
	for _, p := range parts[:len(parts)-1] {
		if d, ok := dir.children[p]; ok && d.isDir {
			dir = d
			continue
		}
		d := &node{name: p, isDir: true, perm: "drwxr-xr-x", owner: "root", group: "root", children: map[string]*node{}}
		dir.children[p] = d
		dir = d
	}
	dir.children[parts[len(parts)-1]] = &node{
		name:    parts[len(parts)-1],
		perm:    perm,
		owner:   owner,
		group:   group,
		size:    int64(len(content)),
		mtime:   time.Now(),
		content: content,
	}
}

func (fs *FileSystem) addDir(path, perm, owner, group string) {
	parts := splitPath(path)
	dir := fs.root
	for _, p := range parts {
		if d, ok := dir.children[p]; ok && d.isDir {
			dir = d
			continue
		}
		d := &node{name: p, isDir: true, perm: perm, owner: owner, group: group, children: map[string]*node{}}
		dir.children[p] = d
		dir = d
	}
}

func (fs *FileSystem) bootstrap(users []string) {
	host := fs.hostname

	// /etc
	passwd := "root:x:0:0:root:/root:/bin/bash\n"
	shadow := "root:$6$rounds=656000$ZyHdQ8m4tZ8mK0n$:19800:0:99999:7:::\n"
	uid := 1000
	for _, u := range users {
		if u == "root" {
			continue
		}
		home := "/home/" + u
		if u == "www-data" {
			home = "/var/www"
		}
		passwd += fmt.Sprintf("%s:x:%d:%d:%s:%s:/bin/bash\n", u, uid, uid, u, home)
		uid++
	}
	passwd += "sshd:x:65534:65534:sshd:/var/run/sshd:/usr/sbin/nologin\n"
	fs.addFile("/etc/passwd", "-rw-r--r--", "root", "root", []byte(passwd))
	fs.addFile("/etc/shadow", "-rw-------", "root", "shadow", []byte(shadow))
	fs.addFile("/etc/hostname", "-rw-r--r--", "root", "root", []byte(host+"\n"))
	fs.addFile("/etc/hosts", "-rw-r--r--", "root", "root",
		[]byte("127.0.0.1\tlocalhost\n127.0.1.1\t"+host+"\n"))
	fs.addFile("/etc/os-release", "-rw-r--r--", "root", "root",
		[]byte("NAME=\"Ubuntu\"\nVERSION=\"22.04.3 LTS (Jammy Jellyfish)\"\nID=ubuntu\nVERSION_ID=\"22.04\"\n"))
	fs.addFile("/etc/motd", "-rw-r--r--", "root", "root",
		[]byte("Welcome to Ubuntu 22.04.3 LTS (GNU/Linux 5.15.0-91-generic x86_64)\n"))
	fs.addFile("/var/log/auth.log", "-rw-r-----", "syslog", "adm",
		[]byte("Aug 18 02:11:03 "+host+" sshd[2312]: Accepted publickey for ubuntu from 10.0.2.15\nAug 19 07:42:11 "+host+" sshd[2319]: Failed password for invalid user admin from 203.0.113.4 port 53321 ssh2\n"))

	// 用户家目录
	fs.addDir("/root", "drwx------", "root", "root")
	fs.addFile("/root/.bash_history", "-rw-------", "root", "root",
		[]byte("ls -la\ncd /var/www\napt update\nwhoami\n"))
	fs.addDir("/home", "drwxr-xr-x", "root", "root")
	for _, u := range users {
		if u == "root" || u == "www-data" {
			continue
		}
		fs.addDir("/home/"+u, "drwxr-xr-x", u, u)
		fs.addFile("/home/"+u+"/.bashrc", "-rw-r--r--", u, u, []byte("# ~/.bashrc\n"))
	}
	fs.addDir("/tmp", "drwxrwxrwt", "root", "root")
	fs.addDir("/var", "drwxr-xr-x", "root", "root")
	fs.addDir("/var/www", "drwxr-xr-x", "root", "root")
	fs.addFile("/var/www/index.html", "-rw-r--r--", "root", "root",
		[]byte("<html><body><h1>It works!</h1></body></html>\n"))
	fs.addDir("/bin", "drwxr-xr-x", "root", "root")
	fs.addDir("/usr", "drwxr-xr-x", "root", "root")
	fs.addDir("/usr/bin", "drwxr-xr-x", "root", "root")
	fs.addDir("/opt", "drwxr-xr-x", "root", "root")
	fs.addDir("/srv", "drwxr-xr-x", "root", "root")
	// 常见"入侵入口"目录
	fs.addDir("/var/tmp", "drwxrwxrwt", "root", "root")
	fs.addDir("/dev/shm", "drwxrwxrwt", "root", "root")
}

// splitPath 把绝对路径拆成各层名字
func splitPath(path string) []string {
	clean := strings.Trim(path, "/")
	if clean == "" {
		return nil
	}
	return strings.Split(clean, "/")
}

func (fs *FileSystem) resolve(path string) (*node, bool) {
	parts := splitPath(path)
	cur := fs.root
	for _, p := range parts {
		if p == "." {
			continue
		}
		if p == ".." {
			// 简化：不支持向上回溯父节点（此处仅需 root 下导航）
			return nil, false
		}
		next, ok := cur.children[p]
		if !ok {
			return nil, false
		}
		cur = next
	}
	return cur, true
}

// Resolve 返回路径对应节点（对外只读视图）
func (fs *FileSystem) Resolve(path string) (info FileInfo, ok bool) {
	fs.mu.RLock()
	defer fs.mu.RUnlock()
	n, found := fs.resolve(path)
	if !found {
		return FileInfo{}, false
	}
	return n.info(), true
}

// List 列出目录内容，返回排序后的条目
func (fs *FileSystem) List(path string) ([]FileInfo, error) {
	fs.mu.RLock()
	defer fs.mu.RUnlock()
	n, ok := fs.resolve(path)
	if !ok {
		return nil, fmt.Errorf("no such file or directory")
	}
	if !n.isDir {
		return nil, fmt.Errorf("not a directory")
	}
	out := make([]FileInfo, 0, len(n.children)+2)
	for _, c := range n.children {
		out = append(out, c.info())
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

// ReadDir2 返回目录条目（io/fs.DirEntry），供 shell 通配符展开
func (fs *FileSystem) ReadDir2(path string) ([]fsys.DirEntry, error) {
	infos, err := fs.List(path)
	if err != nil {
		return nil, err
	}
	out := make([]fsys.DirEntry, 0, len(infos))
	for _, fi := range infos {
		out = append(out, vfsDirEntry{name: fi.Name, isDir: fi.IsDir})
	}
	return out, nil
}

// vfsDirEntry 实现 io/fs.DirEntry
type vfsDirEntry struct {
	name  string
	isDir bool
}

func (d vfsDirEntry) Name() string { return d.name }
func (d vfsDirEntry) IsDir() bool  { return d.isDir }
func (d vfsDirEntry) Type() fsys.FileMode {
	if d.isDir {
		return fsys.ModeDir
	}
	return 0
}
func (d vfsDirEntry) Info() (fsys.FileInfo, error) {
	return nil, fmt.Errorf("Info not supported")
}

// ReadFile 读取文件内容（/proc 下动态生成）
func (fs *FileSystem) ReadFile(path string) ([]byte, error) {
	fs.mu.RLock()
	defer fs.mu.RUnlock()
	n, ok := fs.resolve(path)
	if !ok {
		return nil, fmt.Errorf("no such file or directory")
	}
	if n.isDir {
		return nil, fmt.Errorf("is a directory")
	}
	if content := fs.procContent(path); content != nil {
		return content, nil
	}
	return n.content, nil
}

// IsDir 判断路径是否为目录
func (fs *FileSystem) IsDir(path string) bool {
	fs.mu.RLock()
	defer fs.mu.RUnlock()
	n, ok := fs.resolve(path)
	return ok && n.isDir
}

// WriteFile 覆盖写入（父目录必须存在），M2 用于 echo > / wget 落盘
func (fs *FileSystem) WriteFile(path string, data []byte) error {
	return fs.write(path, data, false)
}

// AppendFile 追加写入，用于 echo >>
func (fs *FileSystem) AppendFile(path string, data []byte) error {
	return fs.write(path, data, true)
}

func (fs *FileSystem) write(path string, data []byte, appendMode bool) error {
	fs.mu.Lock()
	defer fs.mu.Unlock()
	parts := splitPath(path)
	if len(parts) == 0 {
		return fmt.Errorf("invalid path")
	}
	dir := fs.root
	for _, p := range parts[:len(parts)-1] {
		next, ok := dir.children[p]
		if !ok || !next.isDir {
			return fmt.Errorf("no such directory")
		}
		dir = next
	}
	name := parts[len(parts)-1]
	n, exists := dir.children[name]
	if !exists {
		n = &node{name: name, perm: "-rw-r--r--", owner: "root", group: "root", mtime: time.Now()}
		dir.children[name] = n
	} else if n.isDir {
		return fmt.Errorf("is a directory")
	}
	if appendMode {
		n.content = append(n.content, data...)
	} else {
		n.content = append([]byte(nil), data...)
	}
	n.size = int64(len(n.content))
	n.mtime = time.Now()
	return nil
}

// Glob 通配符匹配（支持末层 * ? []），返回绝对路径列表，供 shell 字段展开
func (fs *FileSystem) Glob(pattern string) []string {
	fs.mu.RLock()
	defer fs.mu.RUnlock()
	idx := strings.LastIndex(pattern, "/")
	dirPart, basePart := "/", pattern
	if idx >= 0 {
		dirPart, basePart = pattern[:idx], pattern[idx+1:]
	}
	hasMeta := strings.ContainsAny(basePart, "*?[")
	if !hasMeta {
		if _, ok := fs.resolve(pattern); ok {
			return []string{pattern}
		}
		return nil
	}
	dirNode, ok := fs.resolve(dirPart)
	if !ok || !dirNode.isDir {
		return nil
	}
	var out []string
	for name, child := range dirNode.children {
		if ok, _ := path.Match(basePart, name); ok {
			p := strings.TrimSuffix(dirPart, "/") + "/" + name
			if child.isDir {
				p += "/"
			}
			out = append(out, p)
		}
	}
	sort.Strings(out)
	return out
}

// procContent 动态生成 /proc 下内容
func (fs *FileSystem) procContent(path string) []byte {
	switch path {
	case "/proc/version":
		return []byte("Linux version 5.15.0-91-generic (buildd@lcy02-amd64-046) #101-Ubuntu SMP Tue Nov 14 13:30:08 UTC 2023\n")
	case "/proc/cpuinfo":
		return []byte("processor\t: 0\nvendor_id\t: GenuineIntel\nmodel name\t: Intel(R) Xeon(R) CPU E5-2680 v4 @ 2.40GHz\ncpu MHz\t\t: 2399.996\n")
	case "/proc/meminfo":
		return []byte("MemTotal:       16383952 kB\nMemFree:         4123456 kB\nMemAvailable:   11472544 kB\n")
	case "/proc/uptime":
		return []byte("1234567.89 9876543.21\n")
	}
	return nil
}

// FileInfo 只读文件信息视图
type FileInfo struct {
	Name  string
	IsDir bool
	Perm  string
	Owner string
	Group string
	Size  int64
}

func (n *node) info() FileInfo {
	return FileInfo{Name: n.name, IsDir: n.isDir, Perm: n.perm, Owner: n.owner, Group: n.group, Size: n.size}
}
