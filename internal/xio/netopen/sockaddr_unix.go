//go:build linux || darwin

package netopen

import (
	"context"
	"fmt"
	"runtime"
	"strings"
	"unsafe"

	"github.com/oittaa/socat/internal/parse"
	"github.com/oittaa/socat/internal/xio"
	"golang.org/x/sys/unix"
)

const sockaddrStorageSize = 128

type socketCall struct {
	domain, typ, proto int
	addr               []byte
}

type rawSockaddr struct {
	buf []byte
}

func parseSocketPositional(field, v string) (int, error) {
	if v == "" {
		return 0, nil
	}
	n, err := xio.ParseIntAny(v)
	if err != nil {
		return 0, fmt.Errorf("%s: %w", field, err)
	}
	return n, nil
}

func applyGenericSocketOptions(s parse.Spec, domain, typ, proto int) (int, int, int, error) {
	if v := s.OptionValue("pf", ""); v != "" {
		pf, err := parseClassicSocketPF(v)
		if err != nil {
			return 0, 0, 0, err
		}
		domain = pf
	}
	if o, ok := s.OptionNamed("socktype"); ok {
		n, err := parseVsockSocketInt(o, "socktype")
		if err != nil {
			return 0, 0, 0, err
		}
		typ = n
	}
	if n, set, err := parseSocketProtocolOption(s); err != nil {
		return 0, 0, 0, err
	} else if set {
		proto = n
	}
	return domain, typ, proto, nil
}

func finishSocketCall(s parse.Spec, domain, typ, proto int, addr []byte) (socketCall, error) {
	domain, typ, proto, err := applyGenericSocketOptions(s, domain, typ, proto)
	if err != nil {
		return socketCall{}, err
	}
	return socketCall{domain: domain, typ: typ, proto: proto, addr: addr}, nil
}

func parseSocketAddress(s parse.Spec, paramIndex int) ([]byte, error) {
	addrText := rawSocketAddress(s, paramIndex)
	if addrText == "" {
		addrText = strings.Join(s.Params[paramIndex:], ":")
	}
	if strings.Trim(addrText, ":") == "" {
		return nil, fmt.Errorf("%s requires address", s.Type)
	}
	return xio.ParseSocatData(addrText)
}

func parseSocketStreamCall(s parse.Spec) (socketCall, error) {
	if len(s.Params) < 3 {
		return socketCall{}, fmt.Errorf("%s requires %d parameters", s.Type, 3)
	}
	// Empty domain is 0 (PF_UNSPEC). Empty protocol is 0.
	domain, err := parseSocketPositional("domain", s.Params[0])
	if err != nil {
		return socketCall{}, err
	}
	proto, err := parseSocketPositional("protocol", s.Params[1])
	if err != nil {
		return socketCall{}, err
	}
	addr, err := parseSocketAddress(s, 2)
	if err != nil {
		return socketCall{}, err
	}
	if len(addr) == 0 {
		return socketCall{}, fmt.Errorf("%s requires address", s.Type)
	}
	return finishSocketCall(s, domain, unix.SOCK_STREAM, proto, addr)
}

type socketDgramParams struct {
	domain, typ, proto int
	addr               []byte
}

// parseSocketDgramParams parses SOCKET-SENDTO / SOCKET-DATAGRAM /
// SOCKET-RECV / SOCKET-RECVFROM domain:type:protocol:address.
// Empty domain is 0 (PF_UNSPEC). Empty type is SOCK_DGRAM. Empty protocol is 0.
// Malformed non-empty integers are rejected with a field-specific error.
func parseSocketDgramParams(s parse.Spec) (socketDgramParams, error) {
	var out socketDgramParams
	if len(s.Params) < 4 {
		return out, fmt.Errorf("%s requires domain:type:protocol:address", s.Type)
	}
	domain, err := parseSocketPositional("domain", s.Params[0])
	if err != nil {
		return out, err
	}
	out.domain = domain
	out.typ = unix.SOCK_DGRAM
	if s.Params[1] != "" {
		typ, err := parseSocketPositional("type", s.Params[1])
		if err != nil {
			return out, err
		}
		out.typ = typ
	}
	proto, err := parseSocketPositional("protocol", s.Params[2])
	if err != nil {
		return out, err
	}
	out.proto = proto
	addrText := rawSocketAddress(s, 3)
	if addrText == "" {
		addrText = strings.Join(s.Params[3:], ":")
	}
	addr, err := xio.ParseSocatData(addrText)
	if err != nil {
		return out, err
	}
	out.addr = addr
	return out, nil
}

func parseSocketDgramCall(s parse.Spec) (socketCall, error) {
	p, err := parseSocketDgramParams(s)
	if err != nil {
		return socketCall{}, err
	}
	return finishSocketCall(s, p.domain, p.typ, p.proto, p.addr)
}

// rawSocketAddress extracts the address parameter from Spec.Raw without unquote.
// paramIndex is 0-based among TYPE:p0:p1:p2... (e.g. 2 for CONNECT domain:proto:addr).
// Strips trailing ,options only.
func rawSocketAddress(s parse.Spec, paramIndex int) string {
	raw := s.Raw
	// Drop TYPE: prefix (case-insensitive match of type name).
	up := strings.ToUpper(raw)
	prefix := s.Type + ":"
	if strings.HasPrefix(up, strings.ToUpper(prefix)) {
		raw = raw[len(prefix):]
	} else if i := strings.Index(raw, ":"); i >= 0 {
		raw = raw[i+1:]
	}
	// Cut options at top-level comma (not inside quotes).
	raw = cutTopLevelComma(raw)
	// Walk colon-separated params without unquote; respect quotes.
	parts := splitColonNoUnquote(raw)
	if paramIndex >= len(parts) {
		return ""
	}
	// Address may itself contain colons (IPv6 hex form uses x not : usually).
	// Join remaining params with ':' if more than one (hex uses x separators).
	if paramIndex < len(parts)-1 {
		return strings.Join(parts[paramIndex:], ":")
	}
	return parts[paramIndex]
}

func cutTopLevelComma(s string) string {
	// Raw SOCKET data treats grouping characters as ordinary bytes; only
	// quotes and escapes hide the comma.
	sc := parse.NewSpecScanner(s, false)
	for {
		c, cls, ok := sc.Step()
		if !ok {
			break
		}
		if cls == parse.ClassTop && c == ',' {
			return s[:sc.Pos()-1]
		}
	}
	return s
}

func splitColonNoUnquote(s string) []string {
	if s == "" {
		return nil
	}
	var parts []string
	start := 0
	sc := parse.NewSpecScanner(s, false)
	for {
		c, cls, ok := sc.Step()
		if !ok {
			break
		}
		if cls == parse.ClassTop && c == ':' {
			parts = append(parts, s[start:sc.Pos()-1])
			start = sc.Pos()
		}
	}
	parts = append(parts, s[start:])
	return parts
}

func packRawSockaddr(family int, data []byte) (rawSockaddr, error) {
	if len(data) == 0 {
		return rawSockaddr{}, fmt.Errorf("empty socket address")
	}
	if family < 0 || family > sockaddrFamilyMax() {
		return rawSockaddr{}, fmt.Errorf("domain %d out of range", family)
	}
	hdr := sockaddrHeader(family)
	n := len(hdr) + len(data)
	if n > sockaddrStorageSize {
		return rawSockaddr{}, fmt.Errorf("data too long")
	}
	buf := make([]byte, n)
	copy(buf, hdr)
	copy(buf[len(hdr):], data)
	setSockaddrLen(buf)
	return rawSockaddr{buf: buf}, nil
}

func (sa rawSockaddr) withStorage(fn func(ptr unsafe.Pointer, n uintptr) error) error {
	if len(sa.buf) == 0 {
		return fmt.Errorf("empty socket address")
	}
	if len(sa.buf) > sockaddrStorageSize {
		return fmt.Errorf("data too long")
	}
	var storage [sockaddrStorageSize]byte
	copy(storage[:], sa.buf)
	err := fn(unsafe.Pointer(&storage[0]), uintptr(len(sa.buf))) // #nosec G103 -- bind/connect/sendto need the packed bytes and exact length
	runtime.KeepAlive(storage)
	return err
}

func bindRaw(ctx context.Context, fd int, sa rawSockaddr) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	return sa.withStorage(func(ptr unsafe.Pointer, n uintptr) error {
		_, _, errno := unix.Syscall(unix.SYS_BIND, uintptr(fd), uintptr(ptr), n) // #nosec G103 -- bind(2) uses packed sockaddr bytes
		if errno != 0 {
			return errno
		}
		return nil
	})
}

func connectRaw(ctx context.Context, fd int, sa rawSockaddr) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if ctx.Done() == nil {
		return sysConnect(fd, sa)
	}
	if err := unix.SetNonblock(fd, true); err != nil {
		return err
	}
	err := connectInterruptible(ctx, fd, sa)
	if rerr := unix.SetNonblock(fd, false); err == nil {
		err = rerr
	}
	return err
}

func sysConnect(fd int, sa rawSockaddr) error {
	return sa.withStorage(func(ptr unsafe.Pointer, n uintptr) error {
		_, _, errno := unix.Syscall(unix.SYS_CONNECT, uintptr(fd), uintptr(ptr), n) // #nosec G103 -- connect(2) uses packed sockaddr bytes
		if errno != 0 {
			return errno
		}
		return nil
	})
}

func connectInterruptible(ctx context.Context, fd int, sa rawSockaddr) error {
	errno := connectErrno(fd, sa)
	for {
		if errno == 0 {
			return nil
		}
		if errno == unix.EINPROGRESS {
			return waitUnixConnect(ctx, fd)
		}
		if errno != unix.EAGAIN && errno != unix.EWOULDBLOCK {
			return errno
		}
		if err := waitUnixConnectRetry(ctx); err != nil {
			return err
		}
		errno = connectErrno(fd, sa)
	}
}

func connectErrno(fd int, sa rawSockaddr) unix.Errno {
	var out unix.Errno
	_ = sa.withStorage(func(ptr unsafe.Pointer, n uintptr) error {
		_, _, errno := unix.Syscall(unix.SYS_CONNECT, uintptr(fd), uintptr(ptr), n) // #nosec G103 -- connect(2) uses packed sockaddr bytes
		out = errno
		return nil
	})
	return out
}

func sendtoRaw(fd int, p []byte, sa rawSockaddr) error {
	return sa.withStorage(func(ptr unsafe.Pointer, n uintptr) error {
		var pptr unsafe.Pointer
		if len(p) > 0 {
			pptr = unsafe.Pointer(&p[0]) // #nosec G103 -- sendto(2) payload pointer
		}
		_, _, errno := unix.Syscall6(unix.SYS_SENDTO, uintptr(fd), uintptr(pptr), uintptr(len(p)), 0, uintptr(ptr), n) // #nosec G103 -- sendto(2) uses packed sockaddr bytes
		runtime.KeepAlive(p)
		if errno != 0 {
			return errno
		}
		return nil
	})
}

func applySocketOpts(fd int, s parse.Spec) error {
	if err := xio.ApplyReuse(fd, s, false); err != nil {
		return err
	}
	if err := xio.ApplySocketOptions(fd, s); err != nil {
		return err
	}
	return xio.ApplyGenericSetsockopt(fd, s, xio.SockoptPhasePrebind)
}

func newSocket(domain, typ, proto int) (int, error) {
	fd, err := unix.Socket(domain, typ|sockCloexec, proto)
	if err != nil {
		return -1, err
	}
	if sockCloexec == 0 {
		unix.CloseOnExec(fd)
	}
	return fd, nil
}
