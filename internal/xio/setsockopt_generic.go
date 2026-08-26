package xio

import (
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"syscall"

	"github.com/oittaa/socat/internal/parse"
	"github.com/oittaa/socat/internal/relay"
)

// Classic generic setsockopt family (xio-socket.c opt_setsockopt*).
// Baseline: https://repo.or.cz/socat.git tag-1.8.1.3
// 12c08bf66d709fba17035ce95d85bd218428d9ba. Official master
// af5388c898c7bb60997935aee93c223deba60c4a has the same option/help tree
// (xio-socket.c opt_setsockopt* and applyopt_sockopt_generic).
//
// Phases:
//
//	PREBIND:    setsockopt-listen
//	PASTSOCKET: setsockopt-socket
//	CONNECTED:  setsockopt, setsockopt-bin, setsockopt-int, setsockopt-string,
//	            setsockopt-connected
//
// Types (classic applyopt_sockopt_generic):
//
//	INT:INT:INT    → setsockopt(level, opt, &int, sizeof(int))
//	INT:INT:BIN    → dalan third field (decimal 512 is a C int; xHH is bytes)
//	INT:INT:STRING → C string including the terminating NUL
type SockoptPhase int

const (
	SockoptPhasePrebind SockoptPhase = iota
	SockoptPhasePastSocket
	SockoptPhaseConnected
)

type sockoptValueKind int

const (
	sockoptKindBin sockoptValueKind = iota
	sockoptKindInt
	sockoptKindString
)

// ApplyGenericSetsockopt applies the classic generic setsockopt options that
// belong to phase. Kernel rejection fails the call (classic SETSOCKOPT MSS=1).
func ApplyGenericSetsockopt(fd int, s parse.Spec, phase SockoptPhase) error {
	switch phase {
	case SockoptPhasePrebind:
		return applyNamedGenericSetsockopt(fd, s, "setsockopt-listen", sockoptKindBin)
	case SockoptPhasePastSocket:
		return applyNamedGenericSetsockopt(fd, s, "setsockopt-socket", sockoptKindBin)
	case SockoptPhaseConnected:
		if err := applyNamedGenericSetsockopt(fd, s, "setsockopt", sockoptKindBin); err != nil {
			return err
		}
		if err := applyNamedGenericSetsockopt(fd, s, "setsockopt-bin", sockoptKindBin); err != nil {
			return err
		}
		if err := applyNamedGenericSetsockopt(fd, s, "setsockopt-int", sockoptKindInt); err != nil {
			return err
		}
		if err := applyNamedGenericSetsockopt(fd, s, "setsockopt-string", sockoptKindString); err != nil {
			return err
		}
		return applyNamedGenericSetsockopt(fd, s, "setsockopt-connected", sockoptKindBin)
	default:
		return fmt.Errorf("internal: unknown setsockopt phase %d", phase)
	}
}

func applyNamedGenericSetsockopt(fd int, s parse.Spec, name string, kind sockoptValueKind) error {
	o, ok := s.OptionNamed(name)
	if !ok {
		return nil
	}
	if !o.Has || strings.TrimSpace(o.Value) == "" {
		return fmt.Errorf("%s requires level:optname:value", name)
	}
	return applyGenericSetsockoptValue(fd, name, o.Value, kind)
}

// ApplySetsockoptFD applies a classic INT:INT:BIN setsockopt spec
// (level:opt:dalan). Decimal third fields such as 512 stay C ints, matching
// SETSOCKOPT (setsockopt=6:TCP_MAXSEG:512).
func ApplySetsockoptFD(fd int, spec string) error {
	return applyGenericSetsockoptValue(fd, "setsockopt", spec, sockoptKindBin)
}

func applyGenericSetsockoptValue(fd int, name, spec string, kind sockoptValueKind) error {
	parts := strings.SplitN(spec, ":", 3)
	if len(parts) != 3 {
		return fmt.Errorf("%s requires level:optname:value", name)
	}
	level, err := ParseIntAny(parts[0])
	if err != nil {
		return fmt.Errorf("%s level: %w", name, err)
	}
	opt, err := ParseIntAny(parts[1])
	if err != nil {
		return fmt.Errorf("%s optname: %w", name, err)
	}
	rest := parts[2]
	switch kind {
	case sockoptKindInt:
		n, err := ParseIntAny(rest)
		if err != nil {
			return fmt.Errorf("%s value: %w", name, err)
		}
		if err := setSockoptInt(fd, level, opt, n); err != nil {
			return fmt.Errorf("%s: %w", name, err)
		}
		return nil
	case sockoptKindString:
		b := append([]byte(rest), 0)
		if err := setSockoptBytes(fd, level, opt, b); err != nil {
			return fmt.Errorf("%s: %w", name, err)
		}
		return nil
	default:
		useInt, n, data, err := parseSockoptBin(rest)
		if err != nil {
			return fmt.Errorf("%s value: %w", name, err)
		}
		if useInt {
			if err := setSockoptInt(fd, level, opt, n); err != nil {
				return fmt.Errorf("%s: %w", name, err)
			}
			return nil
		}
		if err := setSockoptBytes(fd, level, opt, data); err != nil {
			return fmt.Errorf("%s: %w", name, err)
		}
		return nil
	}
}

// parseSockoptBin implements classic TYPE_INT_INT_BIN: dalan with default type
// 'i', so a bare decimal such as 512 is sizeof(int) rather than ASCII bytes.
func parseSockoptBin(rest string) (useInt bool, n int, data []byte, err error) {
	s := strings.TrimSpace(rest)
	if isDecimalInt(s) {
		n, err = strconv.Atoi(s)
		return true, n, nil, err
	}
	if len(s) > 1 && (s[0] == 'i' || s[0] == 'I') && isDecimalInt(s[1:]) {
		n, err = strconv.Atoi(s[1:])
		return true, n, nil, err
	}
	data, err = ParseSocatData(s)
	return false, 0, data, err
}

func isDecimalInt(s string) bool {
	if s == "" {
		return false
	}
	if s[0] == '+' || s[0] == '-' {
		s = s[1:]
	}
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

func hasGenericSetsockopt(s parse.Spec, phase SockoptPhase) bool {
	switch phase {
	case SockoptPhasePrebind:
		return s.HasOption("setsockopt-listen")
	case SockoptPhasePastSocket:
		return s.HasOption("setsockopt-socket")
	case SockoptPhaseConnected:
		return s.HasOption("setsockopt") ||
			s.HasOption("setsockopt-bin") ||
			s.HasOption("setsockopt-int") ||
			s.HasOption("setsockopt-string") ||
			s.HasOption("setsockopt-connected")
	default:
		return false
	}
}

// ApplyGenericSetsockoptToConn applies phase options on any syscall.Conn.
// Missing options are a no-op. Present options on a conn that does not
// expose a socket fail; they are never silently ignored.
func ApplyGenericSetsockoptToConn(conn syscall.Conn, s parse.Spec, phase SockoptPhase) error {
	if conn == nil || !hasGenericSetsockopt(s, phase) {
		return nil
	}
	raw, err := conn.SyscallConn()
	if err != nil {
		return err
	}
	var optErr error
	ctrlErr := raw.Control(func(fd uintptr) {
		optErr = ApplyGenericSetsockopt(int(fd), s, phase)
	})
	return errors.Join(ctrlErr, optErr)
}

// ApplyGenericSetsockoptToNetConn unwraps NetConn() wrappers (TLS, WS, timeout)
// then applies phase options. A present option on a non-socket fails.
func ApplyGenericSetsockoptToNetConn(c net.Conn, s parse.Spec, phase SockoptPhase) error {
	if !hasGenericSetsockopt(s, phase) {
		return nil
	}
	c = unwrapNetConn(c)
	if c == nil {
		return fmt.Errorf("setsockopt: connection does not expose a socket")
	}
	sc, ok := c.(syscall.Conn)
	if !ok {
		return fmt.Errorf("setsockopt: connection does not expose a socket")
	}
	return ApplyGenericSetsockoptToConn(sc, s, phase)
}

// ApplyGenericSetsockoptToPacketConn applies phase options on a PacketConn
// (QUIC transport, ListenPacket). Rejects present options when the conn does
// not expose a socket fd.
func ApplyGenericSetsockoptToPacketConn(pc net.PacketConn, s parse.Spec, phase SockoptPhase) error {
	if pc == nil || !hasGenericSetsockopt(s, phase) {
		return nil
	}
	sc, ok := pc.(syscall.Conn)
	if !ok {
		return fmt.Errorf("setsockopt: packet connection does not expose a socket")
	}
	return ApplyGenericSetsockoptToConn(sc, s, phase)
}

func applyGenericSetsockoptToStream(s parse.Spec, stream relay.Stream, phase SockoptPhase) error {
	if !hasGenericSetsockopt(s, phase) {
		return nil
	}
	conns := streamSyscallConns(stream)
	if len(conns) == 0 {
		// Packet-session / TLS / WS / QUIC wrappers are often not
		// syscall.Conn. Those openers apply PH_CONNECTED on the raw fd or
		// PacketConn before wrapping (same split as late buffers). A present
		// option on a live socket must still fail in ApplyTCPConnOpts /
		// ApplyGenericSetsockoptToPacketConn when the conn has no fd.
		return nil
	}
	for _, raw := range conns {
		var optErr error
		ctrlErr := raw.Control(func(fd uintptr) {
			optErr = ApplyGenericSetsockopt(int(fd), s, phase)
		})
		if err := errors.Join(ctrlErr, optErr); err != nil {
			return err
		}
	}
	return nil
}

func unwrapNetConn(c net.Conn) net.Conn {
	for hops := 0; c != nil && hops < 8; hops++ {
		unwrapper, ok := c.(interface{ NetConn() net.Conn })
		if !ok {
			return c
		}
		inner := unwrapper.NetConn()
		if inner == nil || inner == c {
			return c
		}
		c = inner
	}
	return c
}
