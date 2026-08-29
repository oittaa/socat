package xio

import (
	"errors"
	"fmt"
	"net"
	"strings"
	"syscall"

	"github.com/oittaa/socat/internal/parse"
	"github.com/oittaa/socat/internal/relay"
)

// Generic setsockopt options: setsockopt-listen before bind, setsockopt-socket
// after socket(), and setsockopt / setsockopt-bin / setsockopt-int /
// setsockopt-string / setsockopt-connected after connect.
// Value forms: level:opt:int, level:opt:dalan (decimal 512 is a C int; xHH
// is bytes), and level:opt:string (including the terminating NUL).
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

// ApplyGenericSetsockopt applies generic setsockopt options that belong to
// phase. Kernel rejection fails the call. Every matching occurrence is
// applied in original command-line order (aliases are already folded to
// the canonical Name).
func ApplyGenericSetsockopt(fd int, s parse.Spec, phase SockoptPhase) error {
	for _, o := range s.Options {
		if kind, ok := genericSetsockoptKind(o.Name, phase); ok {
			if err := applyGenericSetsockoptOption(fd, o, kind); err != nil {
				return err
			}
			continue
		}
		// Named TCP options after connect (tcp-maxseg-late) share this walk
		// so they apply once with generic connected setsockopt, including
		// on TLS/WS/proxy/SOCKS via ApplyTCPConnOpts.
		if phase == SockoptPhaseConnected {
			if handled, err := applyNamedConnectedSockopt(fd, o); handled {
				if err != nil {
					return err
				}
			}
		}
	}
	return nil
}

// ApplyGenericSetsockoptAll applies every named or generic setsockopt action
// in original command-line order, regardless of its normal lifecycle phase.
// SOCKETPAIR needs this rather than phase-grouped passes. Fixed post-socket()
// options (broadcast, sndbuf, linger, …) share this walk so they are not
// applied before named/generic occurrences.
func ApplyGenericSetsockoptAll(fd int, s parse.Spec) error {
	for _, o := range s.Options {
		if handled, err := applyFixedPastSocketOption(fd, o); handled {
			if err != nil {
				return err
			}
			continue
		}
		if handled, err := applyNamedPastSocketSockopt(fd, o); handled {
			if err != nil {
				return err
			}
			continue
		}
		if handled, err := applyNamedConnectedSockopt(fd, o); handled {
			if err != nil {
				return err
			}
			continue
		}
		_, kind, ok := genericSetsockoptDescriptor(o.Name)
		if !ok {
			continue
		}
		if err := applyGenericSetsockoptOption(fd, o, kind); err != nil {
			return err
		}
	}
	return nil
}

func applyGenericSetsockoptOption(fd int, o parse.Option, kind sockoptValueKind) error {
	if !o.Has || strings.TrimSpace(o.Value) == "" {
		return fmt.Errorf("%s requires level:optname:value", o.Name)
	}
	return applyGenericSetsockoptValue(fd, o.Name, o.Value, kind)
}

func genericSetsockoptKind(name string, phase SockoptPhase) (sockoptValueKind, bool) {
	want, kind, ok := genericSetsockoptDescriptor(name)
	return kind, ok && want == phase
}

func genericSetsockoptDescriptor(name string) (SockoptPhase, sockoptValueKind, bool) {
	switch name {
	case "setsockopt-listen":
		return SockoptPhasePrebind, sockoptKindBin, true
	case "setsockopt-socket":
		return SockoptPhasePastSocket, sockoptKindBin, true
	case "setsockopt", "setsockopt-bin", "setsockopt-connected":
		return SockoptPhaseConnected, sockoptKindBin, true
	case "setsockopt-int":
		return SockoptPhaseConnected, sockoptKindInt, true
	case "setsockopt-string":
		return SockoptPhaseConnected, sockoptKindString, true
	default:
		return 0, 0, false
	}
}

// RejectGenericSetsockoptPhases fails an address/phase combination before it
// can be accepted and silently ignored. FD includes post-socket() options
// but not listen-time or post-connect generic setsockopt.
func RejectGenericSetsockoptPhases(s parse.Spec, address string, phases ...SockoptPhase) error {
	for _, o := range s.Options {
		phase, _, ok := genericSetsockoptDescriptor(o.Name)
		if !ok {
			if !namedConnectedTCPName(o.Name) {
				continue
			}
			phase = SockoptPhaseConnected
		}
		for _, rejected := range phases {
			if phase == rejected {
				return fmt.Errorf("%s: option %q is not supported at this lifecycle phase", address, o.Name)
			}
		}
	}
	return nil
}

// ApplySetsockoptFD applies a level:opt:dalan setsockopt spec. Decimal
// third fields such as 512 stay C ints (setsockopt=6:TCP_MAXSEG:512).
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

// parseSockoptBin parses dalan with default type 'i', so a bare decimal
// such as 512 is sizeof(int) rather than ASCII bytes. Syntax errors are
// returned; unknown typed expressions are never treated as ASCII paths
// (ParseSocatData is for SOCKET address data only).
func parseSockoptBin(rest string) (useInt bool, n int, data []byte, err error) {
	data, singleInt, err := ParseDalan(rest, 'i')
	if err != nil {
		return false, 0, nil, err
	}
	if len(data) == 0 {
		return false, 0, nil, fmt.Errorf("empty dalan value")
	}
	if singleInt {
		return true, nativeCInt(data), data, nil
	}
	return false, 0, data, nil
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
			s.HasOption("setsockopt-connected") ||
			hasNamedConnectedTCP(s)
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
		// syscall.Conn. Those openers apply connected options on the raw fd
		// or PacketConn before wrapping (same split as late buffers). A
		// present option on a live socket must still fail in ApplyTCPConnOpts
		// / ApplyGenericSetsockoptToPacketConn when the conn has no fd.
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
