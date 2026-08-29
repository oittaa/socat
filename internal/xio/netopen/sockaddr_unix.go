//go:build linux || darwin

package netopen

import (
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"

	"github.com/oittaa/socat/internal/parse"
	"github.com/oittaa/socat/internal/xio"
	"golang.org/x/sys/unix"
)

func parseSocketParams(s parse.Spec, n int) (domain, proto int, addr []byte, err error) {
	if len(s.Params) < n {
		return 0, 0, nil, fmt.Errorf("%s requires %d parameters", s.Type, n)
	}
	// Empty domain is tolerated (testaddrs expands $PF_INET6 from procan -c;
	// if empty, infer from address length).
	if s.Params[0] == "" {
		domain = 0
	} else {
		domain, err = strconv.Atoi(s.Params[0])
		if err != nil {
			return 0, 0, nil, fmt.Errorf("domain: %w", err)
		}
	}
	if s.Params[1] == "" {
		proto = 0
	} else {
		proto, err = strconv.Atoi(s.Params[1])
		if err != nil {
			return 0, 0, nil, fmt.Errorf("protocol: %w", err)
		}
	}
	// Prefer raw address text so dalan quote forms (and syntax errors)
	// survive parse unquote. Fall back to joined Params.
	addrText := rawSocketAddress(s, 2)
	if addrText == "" {
		addrText = strings.Join(s.Params[2:], ":")
	}
	// testaddrs uses TYPE::::: — joined params become ":"/"::" with no real data.
	if strings.Trim(addrText, ":") == "" {
		return 0, 0, nil, fmt.Errorf("%s requires address", s.Type)
	}
	addr, err = xio.ParseSocatData(addrText)
	if err != nil {
		return 0, 0, nil, err
	}
	if domain == 0 {
		// Heuristic: IPv6 sockaddr data is ~26 bytes; IPv4 ~14; else UNIX path.
		switch {
		case len(addr) >= 22:
			domain = unix.AF_INET6
		case len(addr) >= 6 && len(addr) <= 16:
			domain = unix.AF_INET
		default:
			domain = unix.AF_UNIX
		}
	}
	return domain, proto, addr, nil
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

// buildSockaddr builds unix.Sockaddr from domain + address data (without family).
func buildSockaddr(domain int, data []byte) (unix.Sockaddr, int, error) {
	if len(data) == 0 {
		return nil, 0, fmt.Errorf("empty socket address")
	}
	switch domain {
	case unix.AF_INET:
		// sockaddr_in data: port(2 BE) + addr(4) + zero(8) = 14 bytes typically
		if len(data) < 6 {
			return nil, 0, fmt.Errorf("AF_INET address too short")
		}
		port := binary.BigEndian.Uint16(data[0:2])
		ip := net.IPv4(data[2], data[3], data[4], data[5])
		sa := &unix.SockaddrInet4{Port: int(port)}
		copy(sa.Addr[:], ip.To4())
		return sa, unix.SizeofSockaddrInet4, nil
	case unix.AF_INET6:
		// port(2) + flowinfo(4) + addr(16) + scope(4) — family may be omitted
		if len(data) < 2+4+16 {
			return nil, 0, fmt.Errorf("AF_INET6 address too short (%d)", len(data))
		}
		port := binary.BigEndian.Uint16(data[0:2])
		// skip flowinfo at 2:6
		var addr [16]byte
		copy(addr[:], data[6:22])
		scope := uint32(0)
		if len(data) >= 26 {
			scope = binary.BigEndian.Uint32(data[22:26])
		}
		sa := &unix.SockaddrInet6{Port: int(port), ZoneId: scope, Addr: addr}
		return sa, unix.SizeofSockaddrInet6, nil
	case unix.AF_UNIX:
		// path bytes, often NUL-terminated
		path := string(data)
		if i := strings.IndexByte(path, 0); i >= 0 {
			path = path[:i]
		}
		return &unix.SockaddrUnix{Name: path}, 2 + len(path) + 1, nil
	default:
		return nil, 0, fmt.Errorf("unsupported socket domain %d", domain)
	}
}

func bindRaw(fd int, sa unix.Sockaddr, _ int) error {
	return unix.Bind(fd, sa)
}

func connectRaw(fd int, sa unix.Sockaddr, _ int) error {
	return unix.Connect(fd, sa)
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

func osNewFile(fd int, name string) *os.File {
	return os.NewFile(uintptr(fd), name)
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
