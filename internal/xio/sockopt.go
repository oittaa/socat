package xio

import (
	"errors"
	"fmt"
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
// applied in WrapCommon, not here.
func applyPastSocketBuffersAndDevice(fd int, s parse.Spec) error {
	o, ok := s.OptionNamed("sndbuf")
	if err := applySocketBufferOpt(fd, "sndbuf", o, ok, soSndbuf); err != nil {
		return err
	}
	o, ok = s.OptionNamed("rcvbuf")
	if err := applySocketBufferOpt(fd, "rcvbuf", o, ok, soRcvbuf); err != nil {
		return err
	}
	return applyBindToDevice(fd, s)
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

func applyLateSocketOptionsToStream(s parse.Spec, stream relay.Stream) error {
	if _, ok := s.OptionNamed("sndbuf-late"); !ok {
		if _, ok := s.OptionNamed("rcvbuf-late"); !ok {
			return nil
		}
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
		if v == nil {
			return
		}
		sc, ok := v.(syscall.Conn)
		if !ok {
			return
		}
		raw, err := sc.SyscallConn()
		if err != nil || raw == nil {
			return
		}
		out = append(out, raw)
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
