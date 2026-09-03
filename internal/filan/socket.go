//go:build linux || darwin

package filan

import (
	"encoding/binary"
	"fmt"
	"runtime"
	"strings"
	"unsafe"

	"github.com/oittaa/socat/internal/outbuf"
	"golang.org/x/sys/unix"
)

const (
	optFmtSocket = iota
	optFmtLayer
)

func printSocket(fd int, b *outbuf.Buf) {
	for _, o := range solSocketOpts() {
		printSockopt(b, fd, o.level, o.opt, o.name, optFmtSocket)
	}
	sa, slen, err := sockname(fd)
	if err != nil {
		return
	}
	b.Printf("\t%s", sockAddrInfo(sa, slen))
	if pa, plen, err := peername(fd); err == nil {
		b.Printf(" <-> %s", sockAddrInfo(pa, plen))
	}
	switch sa.(type) {
	case *unix.SockaddrInet4:
		printIPAndTCP(fd, b, false)
	case *unix.SockaddrInet6:
		printIPAndTCP(fd, b, true)
	}
}

func printIPAndTCP(fd int, b *outbuf.Buf, v6 bool) {
	for _, o := range ipOpts() {
		printSockopt(b, fd, o.level, o.opt, o.name, optFmtLayer)
	}
	if v6 {
		printSockopt(b, fd, unix.IPPROTO_IPV6, unix.IPV6_V6ONLY, "IPV6_V6ONLY", optFmtLayer)
	}
	if !wantTCPOpts(fd) {
		return
	}
	for _, o := range tcpOpts() {
		printSockopt(b, fd, o.level, o.opt, o.name, optFmtLayer)
	}
	printTCPInfoExtra(fd, b)
}

func wantTCPOpts(fd int) bool {
	proto, err := SocketProtocol(fd)
	if err == nil {
		return proto == unix.IPPROTO_TCP
	}
	st, err := unix.GetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_TYPE)
	return err == nil && st == unix.SOCK_STREAM
}

func printSockopt(b *outbuf.Buf, fd, level, opt int, name string, kind int) {
	raw, err := getsockoptBytes(fd, level, opt)
	if err != nil {
		b.Print("\t")
		return
	}
	switch {
	case len(raw) == 0:
		b.Printf("\t%s=\"\"", name)
	case len(raw) == 4:
		b.Printf("\t%s=%d", name, int(int32(nativeUint32(raw)))) // #nosec G115 -- C int is 32-bit two's complement
	case kind == optFmtSocket:
		a, c := 0, 0
		if len(raw) >= 4 {
			a = int(int32(nativeUint32(raw))) // #nosec G115 -- C int is 32-bit two's complement
		}
		if len(raw) >= 8 {
			c = int(int32(nativeUint32(raw[4:]))) // #nosec G115 -- C int is 32-bit two's complement
		}
		b.Printf("\t%s={%d,%d}", name, a, c)
	default:
		var parts []string
		for i := 0; i+4 <= len(raw); i += 4 {
			parts = append(parts, fmt.Sprintf("%08x", nativeUint32(raw[i:])))
		}
		b.Printf("\t%s={%s}", name, strings.Join(parts, " "))
	}
}

func getsockoptBytes(fd, level, opt int) ([]byte, error) {
	const bufLen = 256
	buf := make([]byte, bufLen)
	vallen := uint32(bufLen)
	_, _, errno := unix.Syscall6(
		unix.SYS_GETSOCKOPT,
		uintptr(fd),
		uintptr(level),
		uintptr(opt),
		uintptr(unsafe.Pointer(&buf[0])), // #nosec G103 -- getsockopt needs a kernel buffer
		uintptr(unsafe.Pointer(&vallen)), // #nosec G103 -- socklen_t in/out
		0,
	)
	if errno != 0 {
		return nil, errno
	}
	return buf[:vallen], nil
}

func nativeUint32(b []byte) uint32 {
	return binary.NativeEndian.Uint32(b[:4])
}

func fionread(fd int) (int, error) {
	return unix.IoctlGetInt(fd, fionreadReq)
}

// SockAddrString formats a kernel sockaddr for short (-s/-S) output.
func SockAddrString(sa unix.Sockaddr) string {
	switch a := sa.(type) {
	case *unix.SockaddrInet4:
		return fmt.Sprintf("%d.%d.%d.%d:%d", a.Addr[0], a.Addr[1], a.Addr[2], a.Addr[3], a.Port)
	case *unix.SockaddrInet6:
		return fmt.Sprintf("[%s]:%d", netIPv6(a.Addr, false), a.Port)
	case *unix.SockaddrUnix:
		name := a.Name
		if len(name) > 0 && name[0] == 0 {
			return "@" + name[1:]
		}
		return name
	default:
		return fmt.Sprintf("%T", sa)
	}
}

// SockAddrInfo formats a kernel sockaddr with family (and length on Darwin).
func SockAddrInfo(sa unix.Sockaddr) string {
	return sockAddrInfo(sa, sockaddrLen(sa))
}

func sockAddrInfo(sa unix.Sockaddr, slen int) string {
	var b strings.Builder
	if runtime.GOOS == "darwin" {
		fmt.Fprintf(&b, "LEN=%d ", slen)
	}
	switch a := sa.(type) {
	case *unix.SockaddrInet4:
		fmt.Fprintf(&b, "AF=%d %d.%d.%d.%d:%d", unix.AF_INET, a.Addr[0], a.Addr[1], a.Addr[2], a.Addr[3], a.Port)
	case *unix.SockaddrInet6:
		fmt.Fprintf(&b, "AF=%d [%s]:%d", unix.AF_INET6, netIPv6(a.Addr, true), a.Port)
	case *unix.SockaddrUnix:
		name := a.Name
		if name == "" {
			name = "<anon>"
		} else if name[0] == 0 {
			name = "@" + name[1:]
		}
		fmt.Fprintf(&b, "AF=%d \"%s\"", unix.AF_UNIX, name)
	default:
		fmt.Fprintf(&b, "AF=%d %s", sockaddrFamily(sa), SockAddrString(sa))
	}
	return b.String()
}

func sockname(fd int) (unix.Sockaddr, int, error) {
	sa, err := unix.Getsockname(fd)
	if err != nil {
		return nil, 0, err
	}
	return sa, rawSockaddrLen(fd, false, sa), nil
}

func peername(fd int) (unix.Sockaddr, int, error) {
	sa, err := unix.Getpeername(fd)
	if err != nil {
		return nil, 0, err
	}
	return sa, rawSockaddrLen(fd, true, sa), nil
}

func rawSockaddrLen(fd int, peer bool, sa unix.Sockaddr) int {
	var rsa unix.RawSockaddrAny
	l := uint32(unsafe.Sizeof(rsa)) // #nosec G115 -- socklen_t for sockaddr_storage
	sys := unix.SYS_GETSOCKNAME
	if peer {
		sys = unix.SYS_GETPEERNAME
	}
	_, _, errno := unix.Syscall(uintptr(sys), uintptr(fd), uintptr(unsafe.Pointer(&rsa)), uintptr(unsafe.Pointer(&l))) // #nosec G103 -- getsockname/getpeername write a sockaddr
	if errno != 0 {
		return sockaddrLen(sa)
	}
	if n := kernelSockaddrLen(&rsa, int(l)); n > 0 {
		return n
	}
	return sockaddrLen(sa)
}

func sockaddrLen(sa unix.Sockaddr) int {
	switch a := sa.(type) {
	case *unix.SockaddrInet4:
		return unix.SizeofSockaddrInet4
	case *unix.SockaddrInet6:
		return unix.SizeofSockaddrInet6
	case *unix.SockaddrUnix:
		hdr := int(unsafe.Offsetof(unix.RawSockaddrUnix{}.Path))
		n := len(a.Name)
		if n == 0 {
			return hdr
		}
		if a.Name[0] == 0 {
			return hdr + n
		}
		return hdr + n + 1
	default:
		return 0
	}
}

func sockaddrFamily(sa unix.Sockaddr) int {
	switch sa.(type) {
	case *unix.SockaddrInet4:
		return unix.AF_INET
	case *unix.SockaddrInet6:
		return unix.AF_INET6
	case *unix.SockaddrUnix:
		return unix.AF_UNIX
	default:
		return -1
	}
}

func netIPv6(b [16]byte, padded bool) string {
	words := [8]uint16{
		uint16(b[0])<<8 | uint16(b[1]),
		uint16(b[2])<<8 | uint16(b[3]),
		uint16(b[4])<<8 | uint16(b[5]),
		uint16(b[6])<<8 | uint16(b[7]),
		uint16(b[8])<<8 | uint16(b[9]),
		uint16(b[10])<<8 | uint16(b[11]),
		uint16(b[12])<<8 | uint16(b[13]),
		uint16(b[14])<<8 | uint16(b[15]),
	}
	if padded {
		return fmt.Sprintf("%04x:%04x:%04x:%04x:%04x:%04x:%04x:%04x",
			words[0], words[1], words[2], words[3], words[4], words[5], words[6], words[7])
	}
	return fmt.Sprintf("%x:%x:%x:%x:%x:%x:%x:%x",
		words[0], words[1], words[2], words[3], words[4], words[5], words[6], words[7])
}

type sockopt struct {
	level, opt int
	name       string
}
