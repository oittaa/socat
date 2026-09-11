package xio

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"
	"syscall"

	"github.com/oittaa/socat/internal/addrconfig"
	"github.com/oittaa/socat/internal/parse"
	"github.com/oittaa/socat/internal/relay"
)

// applySocketBufferOpt sets SO_SNDBUF or SO_RCVBUF after socket().
// Linux often doubles the stored value; callers must not require exact equality.
// Late buffers are applied from prepared Network.Actions.
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

// applyBroadcastOption sets SO_BROADCAST. Bare flag → 1; with '=' → integer.
// Presence always applies, including broadcast=0. BoolOption is wrong here
// because it skips false.
func applyBroadcastOption(fd int, o parse.Option) error {
	n := 1
	if o.Has {
		v, err := ParseIntAny(o.Value)
		if err != nil || v < 0 {
			return fmt.Errorf("broadcast: invalid value %q", o.Value)
		}
		n = v
	}
	if err := setSockoptInt(fd, solSocket, soBroadcast, n); err != nil {
		return fmt.Errorf("broadcast: %w", err)
	}
	return nil
}

// applyFixedPastSocketOption applies one post-socket() option: broadcast,
// sndbuf/rcvbuf, bindtodevice, so-linger, or rcvtimeo/sndtimeo. Callers walk
// Spec.Options so these keep command-line order with named SOL_SOCKET/TCP
// options, generic setsockopt-socket, and IP/ancillary options.
// sndbuf-late / rcvbuf-late apply later.
func applyFixedPastSocketOption(fd int, o parse.Option) (bool, error) {
	switch o.Name {
	case "broadcast":
		return true, applyBroadcastOption(fd, o)
	case "sndbuf":
		return true, applySocketBufferOpt(fd, "sndbuf", o, true, soSndbuf)
	case "rcvbuf":
		return true, applySocketBufferOpt(fd, "rcvbuf", o, true, soRcvbuf)
	case "bindtodevice":
		return true, applyBindToDeviceOption(fd, o)
	case "so-linger", "linger":
		return true, applyLingerOption(fd, o)
	case "rcvtimeo", "sndtimeo":
		return true, applySocketTimeoOption(fd, o)
	default:
		return false, nil
	}
}

// ApplySocketOptions applies post-socket() options on a raw descriptor
// whose network is unknown here: fixed SOL_SOCKET options (broadcast,
// sndbuf/rcvbuf, bindtodevice, linger, timeos), named SOL_SOCKET/TCP/SCTP
// options, owner ioctls, and generic setsockopt-socket. IP/ancillary/
// membership options are skipped. Go net sockets and raw SCTP use
// ApplyNetworkSocketOptions with the actual network name.
func ApplySocketOptions(fd int, s parse.Spec) error {
	return applyOrderedPastSocketPhaseOptions(fd, s, "")
}

// isPastSocketActionOption reports whether o would be consumed by
// ApplySocketOptions. User-selected EXEC pipes/pty/nofork must reject this
// leftover set instead of silently ignoring it. sndbuf-late/rcvbuf-late and
// tcp-maxseg-late are not included.
func isPastSocketActionOption(o parse.Option) bool {
	switch o.Name {
	case "broadcast", "sndbuf", "rcvbuf", "bindtodevice",
		"so-linger", "linger", "rcvtimeo", "sndtimeo",
		"fiosetown", "siocspgrp":
		return true
	}
	if _, _, ok, _ := lookupNamedPastSocketInt(o.Name); ok {
		return true
	}
	_, ok := genericSetsockoptKind(o.Name, SockoptPhasePastSocket)
	return ok
}

// ApplyLateSocketOptions applies so-sndbuf-late / so-rcvbuf-late
// (same SO_SNDBUF / SO_RCVBUF constants).
func ApplyLateSocketOptions(fd int, s parse.Spec) error {
	config, err := OpeningConfig(context.Background(), s)
	if err != nil {
		return err
	}
	return applyPreparedLateSocketOptions(fd, config)
}

func applyPreparedLateSocketOptions(fd int, config addrconfig.Address) error {
	for _, action := range config.Network.Actions {
		if action.Kind != addrconfig.SocketActionBuffer || action.Phase != addrconfig.SocketPhaseLate {
			continue
		}
		opt := soSndbuf
		if action.Text == "rcvbuf-late" {
			opt = soRcvbuf
		}
		if err := setSockoptInt(fd, solSocket, opt, action.Number); err != nil {
			return fmt.Errorf("%s: %w", action.Text, err)
		}
	}
	return nil
}

// ApplyLateSocketOptionsToConn applies so-sndbuf-late / so-rcvbuf-late
// on a connected or accepted socket, after connect/accept and before
// SSL/PROXY handshake.
func ApplyLateSocketOptionsToConn(conn syscall.Conn, s parse.Spec) error {
	if conn == nil {
		return nil
	}
	config, err := OpeningConfig(context.Background(), s)
	if err != nil {
		return err
	}
	if !hasLateSocketBuffers(config) {
		return nil
	}
	raw, err := conn.SyscallConn()
	if err != nil {
		return err
	}
	var optErr error
	ctrlErr := raw.Control(func(fd uintptr) {
		optErr = applyPreparedLateSocketOptions(int(fd), config)
	})
	err = errors.Join(ctrlErr, optErr)
	if err == nil || isNotSocketError(err) {
		return nil
	}
	return err
}

// ApplyLateSocketOptionsToPacketConn applies late buffers on a UDP
// PacketConn (QUIC transport, ListenPacket). Rejects enabled late options
// when the conn does not expose a socket fd.
func ApplyLateSocketOptionsToPacketConn(pc net.PacketConn, s parse.Spec) error {
	if pc == nil {
		return nil
	}
	config, err := OpeningConfig(context.Background(), s)
	if err != nil {
		return err
	}
	if !hasLateSocketBuffers(config) {
		return nil
	}
	sc, ok := pc.(syscall.Conn)
	if !ok {
		return fmt.Errorf("sndbuf-late/rcvbuf-late: packet connection does not expose a socket")
	}
	raw, err := sc.SyscallConn()
	if err != nil {
		return err
	}
	var optErr error
	ctrlErr := raw.Control(func(fd uintptr) {
		optErr = applyPreparedLateSocketOptions(int(fd), config)
	})
	err = errors.Join(ctrlErr, optErr)
	if err == nil || isNotSocketError(err) {
		return nil
	}
	return err
}

// ApplyIPSendOptsToPacketConn applies send-side IP options on a UDP PacketConn
// that was not created with ListenControl (tests, leftover callers). QUIC,
// HTTP/3, and raw IP apply the same options once in ListenControl / DialControl
// after socket().
func ApplyIPSendOptsToPacketConn(pc net.PacketConn, s parse.Spec, network string) error {
	if pc == nil || !ipSendRequested(s) {
		return nil
	}
	sc, ok := pc.(syscall.Conn)
	if !ok {
		return fmt.Errorf("ip-ttl/ip-tos: packet connection does not expose a socket")
	}
	raw, err := sc.SyscallConn()
	if err != nil {
		return err
	}
	var optErr error
	ctrlErr := raw.Control(func(fd uintptr) {
		optErr = ApplyIPSendOpts(int(fd), s, network)
	})
	return errors.Join(ctrlErr, optErr)
}

func hasLateSocketBuffers(config addrconfig.Address) bool {
	for _, action := range config.Network.Actions {
		if action.Kind == addrconfig.SocketActionBuffer && action.Phase == addrconfig.SocketPhaseLate {
			return true
		}
	}
	return false
}

// SockoptCall is one test-only observation of setSockoptInt / setSockoptBytes.
type SockoptCall struct {
	FD, Level, Opt int
	AsInt          bool
	IntValue       int
	Bytes          []byte
}

var (
	sockoptHookMu sync.Mutex
	sockoptHook   func(SockoptCall)
)

// SetSockoptTestHook installs a test-only observer around setSockoptInt and
// setSockoptBytes. The returned function restores the previous hook.
func SetSockoptTestHook(h func(SockoptCall)) func() {
	sockoptHookMu.Lock()
	prev := sockoptHook
	sockoptHook = h
	sockoptHookMu.Unlock()
	return func() {
		sockoptHookMu.Lock()
		sockoptHook = prev
		sockoptHookMu.Unlock()
	}
}

func recordSockoptInt(fd, level, opt, value int) {
	sockoptHookMu.Lock()
	h := sockoptHook
	sockoptHookMu.Unlock()
	if h != nil {
		h(SockoptCall{FD: fd, Level: level, Opt: opt, AsInt: true, IntValue: value})
	}
}

func recordSockoptBytes(fd, level, opt int, value []byte) {
	sockoptHookMu.Lock()
	h := sockoptHook
	sockoptHookMu.Unlock()
	if h != nil {
		h(SockoptCall{FD: fd, Level: level, Opt: opt, Bytes: append([]byte(nil), value...)})
	}
}

// ApplyStreamLateSocketOptions applies buffer sizes on exposed sockets.
func ApplyStreamLateSocketOptions(s parse.Spec, stream relay.Stream) error {
	config, err := OpeningConfig(context.Background(), s)
	if err != nil {
		return err
	}
	if !hasLateSocketBuffers(config) {
		return nil
	}
	for _, raw := range streamSyscallConns(stream) {
		var optErr error
		ctrlErr := raw.Control(func(fd uintptr) {
			optErr = applyPreparedLateSocketOptions(int(fd), config)
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
			if h, ok := v.(*halfCloseWriter); ok {
				v = h.w
				continue
			}
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
