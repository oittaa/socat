//go:build linux

package netopen

import (
	"context"
	"fmt"
	"net"
	"os"
	"strconv"
	"syscall"
	"time"

	"github.com/oittaa/socat/internal/logx"
	"github.com/oittaa/socat/internal/parse"
	"github.com/oittaa/socat/internal/xio"
	"golang.org/x/sys/unix"
)

func init() {
	xio.FeatureUDPLITE = true
}

// listenIPDgram creates SOCK_DGRAM + proto (IPPROTO_UDPLITE), binds, and wraps
// the fd. Go net.FilePacketConn keys off SOCK_DGRAM + AF_INET/6, not protocol,
// so the result is *net.UDPConn while SO_PROTOCOL stays 136 (kernel UDP-Lite).
func listenIPDgram(ctx context.Context, network string, laddr *net.UDPAddr, s parse.Spec, proto int) (*net.UDPConn, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if laddr == nil {
		return nil, fmt.Errorf("udplite: missing listen address")
	}
	family := udpFamily(network, laddr)
	fd, err := newSocket(family, unix.SOCK_DGRAM, proto)
	if err != nil {
		return nil, fmt.Errorf("udplite socket: %w", err)
	}
	ctrl := udpListenControl(s)
	if err := ctrl(network, laddr.String(), rawControlFD(fd)); err != nil {
		logx.CloseErr(unix.Close(fd))
		return nil, err
	}
	sa, err := udpSockaddr(family, laddr)
	if err != nil {
		logx.CloseErr(unix.Close(fd))
		return nil, err
	}
	if err := unix.Bind(fd, sa); err != nil {
		logx.CloseErr(unix.Close(fd))
		return nil, fmt.Errorf("udplite bind: %w", err)
	}
	// Classic OFUNC_SOCKOPT at PH_FD (tag-1.8.1.3 xio-udplite.c).
	if err := applyUDPLITECscov(fd, s); err != nil {
		logx.CloseErr(unix.Close(fd))
		return nil, err
	}
	return filePacketUDP(fd, "udplite")
}

func dialIPDgram(ctx context.Context, network string, laddr, raddr *net.UDPAddr, s parse.Spec, proto int, extra func(string, string, syscall.RawConn) error, timeout time.Duration) (*net.UDPConn, error) {
	if raddr == nil {
		return nil, fmt.Errorf("udplite: missing remote address")
	}
	if timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, timeout)
		defer cancel()
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	family := udpFamily(network, raddr)
	if laddr != nil {
		family = udpFamily(network, laddr)
	}
	fd, err := newSocket(family, unix.SOCK_DGRAM, proto)
	if err != nil {
		return nil, fmt.Errorf("udplite socket: %w", err)
	}
	ctrl := xio.DialControl(s, network, extra)
	if err := ctrl(network, raddr.String(), rawControlFD(fd)); err != nil {
		logx.CloseErr(unix.Close(fd))
		return nil, err
	}
	if laddr != nil {
		lsa, err := udpSockaddr(family, laddr)
		if err != nil {
			logx.CloseErr(unix.Close(fd))
			return nil, err
		}
		if err := unix.Bind(fd, lsa); err != nil {
			logx.CloseErr(unix.Close(fd))
			return nil, fmt.Errorf("udplite bind: %w", err)
		}
	}
	rsa, err := udpSockaddr(family, raddr)
	if err != nil {
		logx.CloseErr(unix.Close(fd))
		return nil, err
	}
	if err := unix.Connect(fd, rsa); err != nil {
		logx.CloseErr(unix.Close(fd))
		return nil, err
	}
	// Classic OFUNC_SOCKOPT at PH_FD (tag-1.8.1.3 xio-udplite.c).
	if err := applyUDPLITECscov(fd, s); err != nil {
		logx.CloseErr(unix.Close(fd))
		return nil, err
	}
	return filePacketUDP(fd, "udplite")
}

func applyUDPLITECscov(fd int, s parse.Spec) error {
	send, sendOK := s.OptionNamed("udplite-send-cscov")
	if err := applyUDPLITECscovOpt(fd, "udplite-send-cscov", udpliteSendCscov, send, sendOK); err != nil {
		return err
	}
	recv, recvOK := s.OptionNamed("udplite-recv-cscov")
	return applyUDPLITECscovOpt(fd, "udplite-recv-cscov", udpliteRecvCscov, recv, recvOK)
}

func applyUDPLITECscovOpt(fd int, name string, opt int, o parse.Option, ok bool) error {
	if !ok {
		return nil
	}
	if !o.Has {
		return fmt.Errorf("%s: invalid value %q", name, o.Value)
	}
	n, err := xio.ParseIntAny(o.Value)
	if err != nil {
		return fmt.Errorf("%s: invalid value %q", name, o.Value)
	}
	// Classic OFUNC_SOCKOPT uses IPPROTO_UDPLITE as the sockopt level
	// (tag-1.8.1.3 xio-udplite.c). On Linux that equals SOL_UDPLITE.
	if err := unix.SetsockoptInt(fd, unix.IPPROTO_UDPLITE, opt, n); err != nil {
		return fmt.Errorf("%s: %w", name, err)
	}
	return nil
}

func filePacketUDP(fd int, name string) (*net.UDPConn, error) {
	f := os.NewFile(uintptr(fd), name)
	if f == nil {
		logx.CloseErr(unix.Close(fd))
		return nil, fmt.Errorf("udplite: invalid fd")
	}
	pc, err := net.FilePacketConn(f)
	_ = f.Close()
	if err != nil {
		return nil, err
	}
	c, ok := pc.(*net.UDPConn)
	if !ok {
		logx.CloseQuiet(pc)
		return nil, fmt.Errorf("udplite: unexpected packet conn type %T", pc)
	}
	return c, nil
}

func udpFamily(network string, addr *net.UDPAddr) int {
	switch network {
	case "udp4":
		return unix.AF_INET
	case "udp6":
		return unix.AF_INET6
	default:
		if addr != nil && addr.IP != nil {
			if addr.IP.To4() != nil {
				return unix.AF_INET
			}
			if addr.IP.To16() != nil {
				return unix.AF_INET6
			}
		}
		return unix.AF_INET6
	}
}

func udpSockaddr(family int, addr *net.UDPAddr) (unix.Sockaddr, error) {
	if addr == nil {
		addr = &net.UDPAddr{}
	}
	switch family {
	case unix.AF_INET:
		sa := &unix.SockaddrInet4{Port: addr.Port}
		if ip := addr.IP.To4(); ip != nil {
			copy(sa.Addr[:], ip)
		}
		return sa, nil
	case unix.AF_INET6:
		sa := &unix.SockaddrInet6{Port: addr.Port}
		if addr.IP == nil {
			return sa, nil
		}
		if v4 := addr.IP.To4(); v4 != nil {
			sa.Addr[10], sa.Addr[11] = 0xff, 0xff
			copy(sa.Addr[12:], v4)
			return sa, nil
		}
		if v6 := addr.IP.To16(); v6 != nil {
			copy(sa.Addr[:], v6)
		}
		if addr.Zone != "" {
			zone, err := ipv6ZoneID(addr.Zone)
			if err != nil {
				return nil, err
			}
			sa.ZoneId = zone
		}
		return sa, nil
	default:
		return nil, fmt.Errorf("udplite: unsupported family %d", family)
	}
}

// ipv6ZoneID accepts a numeric zone id or a kernel interface name.
// Unknown names and overflowing indexes are errors (not zone 0).
func ipv6ZoneID(zone string) (uint32, error) {
	if zone == "" {
		return 0, nil
	}
	if n, err := strconv.ParseUint(zone, 10, 32); err == nil {
		return uint32(n), nil
	}
	ifi, err := net.InterfaceByName(zone)
	if err != nil {
		return 0, fmt.Errorf("udplite: IPv6 zone %q: %w", zone, err)
	}
	id, ok := xio.Uint32FromInt(ifi.Index)
	if !ok {
		return 0, fmt.Errorf("udplite: IPv6 zone %q: interface index %d out of range", zone, ifi.Index)
	}
	return id, nil
}

type rawControlFD int

func (fd rawControlFD) Control(f func(uintptr)) error {
	f(uintptr(fd))
	return nil
}

func (fd rawControlFD) Read(func(uintptr) bool) error  { return syscall.EINVAL }
func (fd rawControlFD) Write(func(uintptr) bool) error { return syscall.EINVAL }
