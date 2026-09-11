package xio

import (
	"errors"
	"fmt"
	"net"
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

func hasGenericSetsockopt(s addrconfig.Address, phase SockoptPhase) bool {
	for _, action := range s.Network.Actions {
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

// ApplyGenericSetsockoptToNetConn unwraps NetConn() wrappers, then applies
// phase options. A present option on a non-socket fails.
func ApplyGenericSetsockoptToNetConn(c net.Conn, s addrconfig.Address, phase SockoptPhase) error {
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
func ApplyGenericSetsockoptToPacketConn(pc net.PacketConn, s addrconfig.Address, phase SockoptPhase) error {
	if pc == nil || !hasGenericSetsockopt(s, phase) {
		return nil
	}
	sc, ok := pc.(syscall.Conn)
	if !ok {
		return fmt.Errorf("setsockopt: packet connection does not expose a socket")
	}
	return ApplyGenericSetsockoptToConn(sc, s, phase)
}

func applyGenericSetsockoptToStream(s addrconfig.Address, stream relay.Stream, phase SockoptPhase) error {
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
