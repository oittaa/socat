package xio

import (
	"errors"
	"fmt"
	"net"
	"strings"
	"syscall"

	"github.com/oittaa/socat/internal/addrconfig"
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

// ApplyPreparedGenericSetsockopt applies decoded generic socket actions in
// their original order without reparsing a level, option, or payload.
func ApplyPreparedGenericSetsockopt(fd int, config addrconfig.Address, phase SockoptPhase) error {
	var want addrconfig.SocketPhase
	switch phase {
	case SockoptPhasePrebind:
		want = addrconfig.SocketPhasePrebind
	case SockoptPhasePastSocket:
		want = addrconfig.SocketPhasePastSocket
	case SockoptPhaseConnected:
		want = addrconfig.SocketPhaseConnected
	default:
		return nil
	}
	return applyPreparedGenericPhase(fd, config, want)
}

func applyPreparedGenericPhase(fd int, config addrconfig.Address, phase addrconfig.SocketPhase) error {
	for _, action := range config.Network.Actions {
		if action.Kind != addrconfig.SocketActionGeneric || action.Phase != phase {
			continue
		}
		if err := applyPreparedGenericAction(fd, action); err != nil {
			return err
		}
	}
	return nil
}

func preparedSocketPhaseMatches(action addrconfig.SocketPhase, phase SockoptPhase) bool {
	switch phase {
	case SockoptPhasePrebind:
		return action == addrconfig.SocketPhasePrebind
	case SockoptPhasePastSocket:
		return action == addrconfig.SocketPhasePastSocket
	case SockoptPhaseConnected:
		return action == addrconfig.SocketPhaseConnected
	default:
		return false
	}
}

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
func ApplyGenericSetsockopt(fd int, s addrconfig.Address, phase SockoptPhase) error {
	config := s
	if phase == SockoptPhaseConnected {
		return applyPreparedSocketPhase(fd, config, socketApplyConnected, "")
	}
	return ApplyPreparedGenericSetsockopt(fd, config, phase)
}

// ApplyGenericSetsockoptAll applies every named or generic setsockopt action
// in original command-line order, regardless of its normal lifecycle phase.
// SOCKETPAIR needs this rather than phase-grouped passes. Fixed post-socket()
// options (broadcast, sndbuf, linger, …) share this walk so they are not
// applied before named/generic occurrences.
func ApplyGenericSetsockoptAll(fd int, s addrconfig.Address) error {
	config := s
	return applyPreparedSocketPhase(fd, config, socketApplySocketpair, "")
}

// RejectGenericSetsockoptPhases fails an address/phase combination before it
// can be accepted and silently ignored. FD includes post-socket() options
// but not listen-time or post-connect generic setsockopt.
func RejectGenericSetsockoptPhases(config addrconfig.Address, address string, phases ...SockoptPhase) error {
	for _, action := range config.Network.Actions {
		phase, name, ok := genericRejectPhase(action)
		if !ok {
			continue
		}
		for _, rejected := range phases {
			if phase == rejected {
				return fmt.Errorf("%s: option %q is not supported at this lifecycle phase", address, name)
			}
		}
	}
	return nil
}

func genericRejectPhase(action addrconfig.SocketAction) (SockoptPhase, string, bool) {
	switch action.Kind {
	case addrconfig.SocketActionGeneric:
		name := action.Text
		if name == "" {
			name = "setsockopt"
		}
		switch action.Phase {
		case addrconfig.SocketPhasePrebind:
			return SockoptPhasePrebind, name, true
		case addrconfig.SocketPhasePastSocket:
			return SockoptPhasePastSocket, name, true
		case addrconfig.SocketPhaseConnected:
			return SockoptPhaseConnected, name, true
		}
	case addrconfig.SocketActionNamed:
		if action.Named == addrconfig.NamedSocketTCPMaxSegLate {
			return SockoptPhaseConnected, namedSocketOptionName(action.Named), true
		}
	}
	return 0, "", false
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

func hasGenericSetsockopt(s addrconfig.Address, phase SockoptPhase) (bool, error) {
	config := s
	return hasPreparedGenericSetsockopt(config, phase), nil
}

func hasPreparedGenericSetsockopt(config addrconfig.Address, phase SockoptPhase) bool {
	for _, action := range config.Network.Actions {
		if !preparedSocketPhaseMatches(action.Phase, phase) {
			continue
		}
		if action.Kind == addrconfig.SocketActionGeneric {
			return true
		}
		if phase == SockoptPhaseConnected && action.Kind == addrconfig.SocketActionNamed && action.Named == addrconfig.NamedSocketTCPMaxSegLate {
			return true
		}
	}
	return false
}

// ApplyGenericSetsockoptToConn applies phase options on any syscall.Conn.
// Missing options are a no-op. Present options on a conn that does not
// expose a socket fail; they are never silently ignored.
func ApplyGenericSetsockoptToConn(conn syscall.Conn, s addrconfig.Address, phase SockoptPhase) error {
	has, err := hasGenericSetsockopt(s, phase)
	if err != nil {
		return err
	}
	if conn == nil || !has {
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

// ApplyGenericSetsockoptToNetConn unwraps NetConn() wrappers, then applies
// phase options. A present option on a non-socket fails.
func ApplyGenericSetsockoptToNetConn(c net.Conn, s addrconfig.Address, phase SockoptPhase) error {
	has, err := hasGenericSetsockopt(s, phase)
	if err != nil {
		return err
	}
	if !has {
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
func ApplyGenericSetsockoptToPacketConn(pc net.PacketConn, s addrconfig.Address, phase SockoptPhase) error {
	has, err := hasGenericSetsockopt(s, phase)
	if err != nil {
		return err
	}
	if pc == nil || !has {
		return nil
	}
	sc, ok := pc.(syscall.Conn)
	if !ok {
		return fmt.Errorf("setsockopt: packet connection does not expose a socket")
	}
	return ApplyGenericSetsockoptToConn(sc, s, phase)
}

func applyGenericSetsockoptToStream(s addrconfig.Address, stream relay.Stream, phase SockoptPhase) error {
	has, err := hasGenericSetsockopt(s, phase)
	if err != nil {
		return err
	}
	if !has {
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
