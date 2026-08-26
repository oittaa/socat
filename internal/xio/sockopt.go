package xio

import (
	"errors"
	"fmt"
	"net"
	"syscall"

	"github.com/oittaa/socat/internal/parse"
	"github.com/oittaa/socat/internal/relay"
)

// applySocketBufferOpt sets SO_SNDBUF or SO_RCVBUF (classic xio-socket.c
// TYPE_INT). so-sndbuf/so-rcvbuf are PH_PASTSOCKET; so-sndbuf-late/
// so-rcvbuf-late are PH_LATE. Linux often doubles the stored value for
// bookkeeping; callers must not require exact equality.
// Classic: tag-1.8.1.3 12c08bf66d709fba17035ce95d85bd218428d9ba;
// official master af5388c898c7bb60997935aee93c223deba60c4a is the same tree.
func applySocketBufferOpt(fd int, name string, o parse.Option, present bool, opt int) error {
	if !present {
		return nil
	}
	if !o.Has {
		return fmt.Errorf("%s: invalid value %q", name, o.Value)
	}
	n, err := ParseIntAny(o.Value)
	if err != nil || n < 0 {
		return fmt.Errorf("%s: invalid value %q", name, o.Value)
	}
	if err := setSockoptInt(fd, solSocket, opt, n); err != nil {
		return fmt.Errorf("%s: %w", name, err)
	}
	return nil
}

// applyPastSocketBuffersAndDevice is the PH_PASTSOCKET half of classic
// opt_so_sndbuf / opt_so_rcvbuf / opt_so_bindtodevice. Late variants are
// applied in ApplyTCPConnOpts (raw TCP after connect/accept, before TLS/
// PROXY handshake), ApplyUDPConnOpts / applyUnixgramSocketOptions (raw
// UDP/UNIX after bind or connect, before packet-session wrapping), and
// WrapCommon (streams that expose a socket fd).
func applyPastSocketBuffersAndDevice(fd int, s parse.Spec) error {
	o, ok := s.OptionNamed("sndbuf")
	if err := applySocketBufferOpt(fd, "sndbuf", o, ok, soSndbuf); err != nil {
		return err
	}
	o, ok = s.OptionNamed("rcvbuf")
	if err := applySocketBufferOpt(fd, "rcvbuf", o, ok, soRcvbuf); err != nil {
		return err
	}
	if err := applyBindToDevice(fd, s); err != nil {
		return err
	}
	return ApplyGenericSetsockopt(fd, s, SockoptPhasePastSocket)
}

// ApplyLateSocketOptions applies classic so-sndbuf-late / so-rcvbuf-late
// (PH_LATE, same SO_SNDBUF / SO_RCVBUF constants).
func ApplyLateSocketOptions(fd int, s parse.Spec) error {
	o, ok := s.OptionNamed("sndbuf-late")
	if err := applySocketBufferOpt(fd, "sndbuf-late", o, ok, soSndbuf); err != nil {
		return err
	}
	o, ok = s.OptionNamed("rcvbuf-late")
	return applySocketBufferOpt(fd, "rcvbuf-late", o, ok, soRcvbuf)
}

// ApplyLateSocketOptionsToConn applies PH_LATE so-sndbuf-late / so-rcvbuf-late
// on a connected or accepted socket. Classic applies these on the raw fd
// after connect()/accept(), before SSL/PROXY handshake.
func ApplyLateSocketOptionsToConn(conn syscall.Conn, s parse.Spec) error {
	if conn == nil {
		return nil
	}
	if !hasLateSocketBuffers(s) {
		return nil
	}
	raw, err := conn.SyscallConn()
	if err != nil {
		return err
	}
	var optErr error
	ctrlErr := raw.Control(func(fd uintptr) {
		optErr = ApplyLateSocketOptions(int(fd), s)
	})
	err = errors.Join(ctrlErr, optErr)
	if err == nil || isNotSocketError(err) {
		return nil
	}
	return err
}

// ApplyLateSocketOptionsToPacketConn applies PH_LATE buffers on a UDP
// PacketConn (QUIC transport, ListenPacket). Rejects enabled late options
// when the conn does not expose a socket fd.
func ApplyLateSocketOptionsToPacketConn(pc net.PacketConn, s parse.Spec) error {
	if pc == nil || !hasLateSocketBuffers(s) {
		return nil
	}
	sc, ok := pc.(syscall.Conn)
	if !ok {
		return fmt.Errorf("sndbuf-late/rcvbuf-late: packet connection does not expose a socket")
	}
	return ApplyLateSocketOptionsToConn(sc, s)
}

func hasLateSocketBuffers(s parse.Spec) bool {
	if _, ok := s.OptionNamed("sndbuf-late"); ok {
		return true
	}
	_, ok := s.OptionNamed("rcvbuf-late")
	return ok
}

func applyLateSocketOptionsToStream(s parse.Spec, stream relay.Stream) error {
	if !hasLateSocketBuffers(s) {
		return nil
	}
	for _, raw := range streamSyscallConns(stream) {
		var optErr error
		ctrlErr := raw.Control(func(fd uintptr) {
			optErr = ApplyLateSocketOptions(int(fd), s)
		})
		err := errors.Join(ctrlErr, optErr)
		if err == nil || isNotSocketError(err) {
			continue
		}
		return err
	}
	return nil
}

func streamSyscallConns(stream relay.Stream) []syscall.RawConn {
	var out []syscall.RawConn
	add := func(v any) {
		for hops := 0; v != nil && hops < 8; hops++ {
			if sc, ok := v.(syscall.Conn); ok {
				raw, err := sc.SyscallConn()
				if err != nil || raw == nil {
					return
				}
				out = append(out, raw)
				return
			}
			unwrapper, ok := v.(interface{ NetConn() net.Conn })
			if !ok {
				return
			}
			next := unwrapper.NetConn()
			if next == nil || next == v {
				return
			}
			v = next
		}
	}
	switch s := stream.(type) {
	case relay.NetStream:
		add(s.Conn)
	case relay.FDStream:
		add(s.R)
		add(s.W)
		add(s.C)
	case relay.RWCStream:
		add(s.ReadWriteCloser)
	default:
		add(stream)
	}
	return out
}
