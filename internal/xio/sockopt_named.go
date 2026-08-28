package xio

import (
	"errors"
	"fmt"

	"github.com/oittaa/socat/internal/parse"
)

// Named SOL_SOCKET, TCP, and Linux SCTP options from classic xio-socket.c /
// xio-tcp.c / xio-sctp.c (https://repo.or.cz/socat.git tag-1.8.1.3
// 12c08bf66d709fba17035ce95d85bd218428d9ba; official master
// af5388c898c7bb60997935aee93c223deba60c4a is the same option/help tree).
//
// PH_PASTSOCKET TYPE_INT OFUNC_SOCKOPT:
//
//	so-debug / debug, so-dontroute / dontroute, so-oobinline / oobinline
//	so-priority / priority, so-passcred / passcred,
//	so-no-check / no-check / nocheck (Linux SO_PRIORITY / SO_PASSCRED /
//	SO_NO_CHECK; classic xio-socket.c #ifdef SO_*)
//	tcp-cork / cork, tcp-defer-accept / defer-accept, tcp-linger2 / linger2,
//	tcp-maxseg / maxseg / mss, tcp-quickack / quickack, tcp-syncnt / syncnt,
//	tcp-window-clamp / window-clamp
//	nopush / tcp-nopush, noopt / tcp-noopt (Darwin/BSD TCP_NOPUSH / TCP_NOOPT;
//	Linux and Windows reject instead of no-op)
//	sctp-nodelay, sctp-maxseg (Linux SOL_SCTP; not TCP_NODELAY / TCP_MAXSEG)
//
// PH_CONNECTED TYPE_INT OFUNC_SOCKOPT:
//
//	tcp-maxseg-late / maxseg-late / mss-late (same TCP_MAXSEG as tcp-maxseg)
//
// Bare flag → 1 (classic TYPE_INT without '='). Kernel rejection fails the
// call. so-bsdcompat is catalog-advertised on Linux glibc but this kernel
// accepts setsockopt and leaves getsockopt at 0, so it is not implemented
// (do not advertise a no-op). tcp-info and tcp-md5sig are later PRs.
// sctp-maxseg-late is not implemented (undocumented optionnames[] alias).
var errNamedOptUnsupported = errors.New("not supported on this platform")

func parseTypeIntSockopt(o parse.Option) (int, error) {
	if !o.Has {
		return 1, nil
	}
	n, err := ParseIntAny(o.Value)
	if err != nil {
		return 0, fmt.Errorf("%s: invalid value %q", o.Name, o.Value)
	}
	return n, nil
}

func applyNamedIntSockopt(fd int, o parse.Option, level, opt int) error {
	n, err := parseTypeIntSockopt(o)
	if err != nil {
		return err
	}
	if err := setSockoptInt(fd, level, opt, n); err != nil {
		return fmt.Errorf("%s: %w", o.Name, err)
	}
	return nil
}

// applyNamedPastSocketSockopt applies one classic PH_PASTSOCKET named
// SOL_SOCKET, TCP, or Linux SCTP TYPE_INT option. Its callers walk
// Spec.Options so named, fixed PASTSOCKET (broadcast/sndbuf/linger/…),
// generic setsockopt-socket, and IP options retain command-line order.
func applyNamedPastSocketSockopt(fd int, o parse.Option) (bool, error) {
	level, opt, ok, err := lookupNamedPastSocketInt(o.Name)
	if !ok {
		return false, nil
	}
	if err != nil {
		return true, fmt.Errorf("%s: %w", o.Name, err)
	}
	return true, applyNamedIntSockopt(fd, o, level, opt)
}

// applyNamedConnectedSockopt applies PH_CONNECTED named TCP options
// (tcp-maxseg-late). It is invoked from ApplyGenericSetsockopt's CONNECTED
// walk so TLS/WS/proxy/SOCKS (ApplyTCPConnOpts) and WrapCommon fallbacks
// share one pass and do not apply CONNECTED generic setsockopt twice.
func applyNamedConnectedSockopt(fd int, o parse.Option) (bool, error) {
	level, opt, ok, err := lookupNamedConnectedInt(o.Name)
	if !ok {
		return false, nil
	}
	if err != nil {
		return true, fmt.Errorf("%s: %w", o.Name, err)
	}
	return true, applyNamedIntSockopt(fd, o, level, opt)
}

func hasNamedConnectedTCP(s parse.Spec) bool {
	for _, o := range s.Options {
		if _, _, ok, _ := lookupNamedConnectedInt(o.Name); ok {
			return true
		}
	}
	return false
}

func namedConnectedTCPName(name string) bool {
	_, _, ok, _ := lookupNamedConnectedInt(name)
	return ok
}
