//go:build unix

package xio

import (
	"fmt"
	"unsafe"

	"golang.org/x/sys/unix"
)

const (
	ipLevelIP        = unix.IPPROTO_IP
	ipOptTTL         = unix.IP_TTL
	ipOptTOS         = unix.IP_TOS
	ipLevelIPv6      = unix.IPPROTO_IPV6
	ipOptUnicastHops = unix.IPV6_UNICAST_HOPS
	// classic applyopt_sockopt_append TYPE_BIN uses a 256-byte getsockopt buffer.
	maxIPOptions = 256
)

func socketIPFamily(fd int) (ipFamily, error) {
	sa, err := unix.Getsockname(fd)
	if err != nil {
		return ipFamilyUnknown, err
	}
	switch sa.(type) {
	case *unix.SockaddrInet4:
		return ipFamilyV4, nil
	case *unix.SockaddrInet6:
		return ipFamilyV6, nil
	default:
		return ipFamilyUnknown, nil
	}
}

func applyIPOptions(fd int, value string) error {
	b, err := ParseHexOpt(value)
	if err != nil {
		return err
	}
	if len(b) == 0 {
		return fmt.Errorf("empty value")
	}
	return appendSockoptIPOptions(fd, b)
}

func sockoptIPOptions(fd int) ([]byte, error) {
	buf := make([]byte, maxIPOptions)
	vallen := uint32(len(buf))        // #nosec G115 -- maxIPOptions is 256, within uint32
	optval := unsafe.Pointer(&buf[0]) // #nosec G103 -- classic OFUNC_SOCKOPT_APPEND reads IP_OPTIONS bytes; GetsockoptString truncates at NUL padding
	optlen := unsafe.Pointer(&vallen) // #nosec G103 -- socklen_t pointer for getsockopt
	_, _, errno := unix.Syscall6(unix.SYS_GETSOCKOPT, uintptr(fd), uintptr(unix.IPPROTO_IP), uintptr(unix.IP_OPTIONS), uintptr(optval), uintptr(optlen), 0)
	if errno != 0 {
		return nil, errno
	}
	n := int(vallen)
	if n > len(buf) {
		n = len(buf)
	}
	out := make([]byte, n)
	copy(out, buf[:n])
	return out, nil
}

// appendSockoptIPOptions is classic OFUNC_SOCKOPT_APPEND for IP_OPTIONS
// (xioopts.c applyopt_sockopt_append TYPE_BIN; xio-ip.c opt_ip_options;
// tag-1.8.1.3 12c08bf66d709fba17035ce95d85bd218428d9ba; official master
// af5388c898c7bb60997935aee93c223deba60c4a is the same tree): getsockopt the
// current value into a 256-byte buffer, memcpy-append the new occurrence
// (capped at 256), then setsockopt the combined data. Each ip-options=
// occurrence appends; they do not replace each other.
func appendSockoptIPOptions(fd int, extra []byte) error {
	old, err := sockoptIPOptions(fd)
	if err != nil {
		return err
	}
	room := maxIPOptions - len(old)
	if len(extra) < room {
		room = len(extra)
	}
	combined := make([]byte, len(old)+room)
	copy(combined, old)
	copy(combined[len(old):], extra[:room])
	return unix.SetsockoptString(fd, unix.IPPROTO_IP, unix.IP_OPTIONS, string(combined))
}

func applyIPv6Tclass(fd, n int) error {
	return setSockoptInt(fd, unix.IPPROTO_IPV6, unix.IPV6_TCLASS, n)
}
