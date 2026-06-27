// SPDX-License-Identifier: GPL-3.0-only
//
// benbackupd - minimal privileged read helper for the BenOS updater backup.
// Go port.

package main

import (
	"encoding/binary"
	"io"
	"log"
	"os"
	"strconv"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"
)

const socketName = "benbackupd"

var allowedRoots = []string{
	"/data/user/",
	"/data/user_de/",
	"/data/data/",
	"/data/app/",
	"/storage/emulated/",
	"/mnt/expand/",
}

func pathAllowed(p string) bool {
	if p == "" || p[0] != '/' {
		return false
	}
	if strings.Contains(p, "/../") {
		return false
	}
	if strings.HasSuffix(p, "/..") {
		return false
	}
	for _, root := range allowedRoots {
		if strings.HasPrefix(p, root) {
			return true
		}
	}
	return false
}

// ---- framed writes ----

func writeAll(fd int, buf []byte) bool {
	for len(buf) > 0 {
		n, err := unix.Write(fd, buf)
		if err == unix.EINTR {
			continue
		}
		if err != nil || n == 0 {
			return false
		}
		buf = buf[n:]
	}
	return true
}

func appendU8(b []byte, v uint8) []byte { return append(b, v) }

func appendU16(b []byte, v uint16) []byte {
	var a [2]byte
	binary.LittleEndian.PutUint16(a[:], v)
	return append(b, a[:]...)
}

func appendU32(b []byte, v uint32) []byte {
	var a [4]byte
	binary.LittleEndian.PutUint32(a[:], v)
	return append(b, a[:]...)
}

func appendU64(b []byte, v uint64) []byte {
	var a [8]byte
	binary.LittleEndian.PutUint64(a[:], v)
	return append(b, a[:]...)
}

func appendI64(b []byte, v int64) []byte { return appendU64(b, uint64(v)) }

func appendLenString(b []byte, s string) []byte {
	n := len(s)
	if n > 0xFFFF {
		n = 0xFFFF
	}
	b = appendU16(b, uint16(n))
	return append(b, s[:n]...)
}

// ---- LIST ----

func typeOf(st os.FileInfo) uint8 {
	switch {
	case st.Mode().IsRegular():
		return 1
	case st.Mode().IsDir():
		return 2
	case st.Mode()&os.ModeSymlink != 0:
		return 3
	case st.Mode()&os.ModeNamedPipe != 0:
		return 4
	}
	return 0
}

func emitNode(client int, rel string, st os.FileInfo, link string) {
	typ := typeOf(st)
	if typ == 0 {
		return
	}
	sys, ok := st.Sys().(*syscall.Stat_t)
	if !ok {
		return
	}

	rec := make([]byte, 0, 64+len(rel)+len(link))
	rec = appendU8(rec, typ)
	rec = appendU32(rec, uint32(sys.Mode&07777))
	rec = appendU32(rec, uint32(sys.Uid))
	rec = appendU32(rec, uint32(sys.Gid))
	var size uint64
	if st.Mode().IsRegular() {
		size = uint64(st.Size())
	}
	rec = appendU64(rec, size)
	rec = appendI64(rec, sys.Mtim.Sec)
	rec = appendU32(rec, uint32(sys.Mtim.Nsec))
	rec = appendLenString(rec, rel)
	rec = appendLenString(rec, link)
	writeAll(client, rec)
}

func walkDir(client int, absRoot, rel string) {
	abs := absRoot
	if rel != "" {
		abs = absRoot + "/" + rel
	}
	f, err := os.Open(abs)
	if err != nil {
		return
	}
	defer f.Close()

	entries, err := f.Readdir(-1)
	if err != nil {
		return
	}
	var subdirs []string
	for _, st := range entries {
		name := st.Name()
		if name == "." || name == ".." {
			continue
		}
		childRel := name
		if rel != "" {
			childRel = rel + "/" + name
		}

		link := ""
		if st.Mode()&os.ModeSymlink != 0 {
			if l, err := os.Readlink(absRoot + "/" + childRel); err == nil {
				link = l
			}
		}
		emitNode(client, childRel, st, link)
		if st.IsDir() {
			subdirs = append(subdirs, childRel)
		}
	}
	for _, s := range subdirs {
		walkDir(client, absRoot, s)
	}
}

func handleList(client int, path string) {
	if pathAllowed(path) {
		st, err := os.Lstat(path)
		if err == nil && st.IsDir() {
			walkDir(client, path, "")
		}
	}
	writeAll(client, []byte{0xFF})
}

// ---- READ ----

func handleRead(client int, path string) {
	if !pathAllowed(path) {
		writeAll(client, []byte{1})
		return
	}
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		writeAll(client, []byte{1})
		return
	}
	defer unix.Close(fd)

	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil || (st.Mode&unix.S_IFMT) != unix.S_IFREG {
		writeAll(client, []byte{1})
		return
	}
	writeAll(client, []byte{0})
	size := uint64(st.Size)
	writeAll(client, appendU64(nil, size))

	buf := make([]byte, 256*1024)
	remaining := size
	for remaining > 0 {
		want := len(buf)
		if remaining < uint64(want) {
			want = int(remaining)
		}
		n, err := unix.Read(fd, buf[:want])
		if err == unix.EINTR {
			continue
		}
		if n <= 0 || err != nil {
			break
		}
		if !writeAll(client, buf[:n]) {
			break
		}
		remaining -= uint64(n)
	}
}

// ---- request loop ----

func recvAll(fd int, buf []byte) (int, error) {
	total := 0
	for total < len(buf) {
		n, err := unix.Read(fd, buf[total:])
		if err == unix.EINTR {
			continue
		}
		if err != nil {
			return total, err
		}
		if n == 0 {
			return total, io.EOF
		}
		total += n
	}
	return total, nil
}

func serveClient(client int) {
	hdr := make([]byte, 3)
	n, err := recvAll(client, hdr)
	if n != 3 || err != nil {
		return
	}
	op := hdr[0]
	pathLen := binary.LittleEndian.Uint16(hdr[1:3])
	path := ""
	if pathLen > 0 {
		buf := make([]byte, pathLen)
		n, err = recvAll(client, buf)
		if n != int(pathLen) || err != nil {
			return
		}
		path = string(buf)
	}
	switch op {
	case 'L':
		handleList(client, path)
	case 'R':
		handleRead(client, path)
	}
}

func main() {
	if f, err := os.OpenFile("/dev/kmsg", os.O_WRONLY, 0); err == nil {
		log.SetOutput(f)
	}

	envName := "ANDROID_SOCKET_" + socketName
	fdStr := os.Getenv(envName)
	if fdStr == "" {
		log.Fatalf("Failed to get control socket %s", socketName)
	}
	fd, err := strconv.Atoi(fdStr)
	if err != nil {
		log.Fatalf("Invalid fd in %s: %v", envName, err)
	}
	if _, err := unix.GetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_TYPE); err != nil {
		log.Fatalf("Invalid control socket fd %d: %v", fd, err)
	}
	if err := unix.Listen(fd, 8); err != nil {
		log.Fatalf("listen failed: %v", err)
	}
	log.Printf("benbackupd ready")

	for {
		client, _, err := unix.Accept(fd)
		if err != nil {
			if err == unix.EINTR {
				continue
			}
			log.Printf("accept failed: %v", err)
			continue
		}
		unix.CloseOnExec(client)
		serveClient(client)
		unix.Close(client)
	}
}
