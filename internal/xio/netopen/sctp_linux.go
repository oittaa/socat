//go:build linux

package netopen

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"syscall"
	"time"

	"github.com/oittaa/socat/internal/logx"
	"github.com/oittaa/socat/internal/parse"
	"github.com/oittaa/socat/internal/xio"
	"golang.org/x/sys/unix"
)

func init() {
	xio.FeatureSCTP = true
}

func listenSCTP(_ context.Context, network, host, port string, s parse.Spec) (net.Listener, error) {
	portNum, err := xio.ResolvePortNum(network, port)
	if err != nil {
		return nil, err
	}
	ip := net.ParseIP(xio.StripBrackets(host))
	family := unix.AF_INET
	switch network {
	case "sctp6":
		family = unix.AF_INET6
		if ip != nil && xio.WantIPv4(network, ip) {
			return nil, fmt.Errorf("bind: address family mismatch (%s on %s)", host, network)
		}
		if ip == nil {
			ip = net.IPv6zero
		}
	case "sctp":
		family = unix.AF_INET6
		if ip == nil {
			ip = net.IPv6zero
		}
	default:
		if ip != nil && ip.To4() == nil {
			return nil, fmt.Errorf("bind: address family mismatch (%s on %s)", host, network)
		}
		if ip == nil {
			ip = net.IPv4zero
		}
	}
	fd, err := newSocket(family, unix.SOCK_STREAM, unix.IPPROTO_SCTP)
	if err != nil {
		return nil, fmt.Errorf("sctp socket: %w", err)
	}
	if err := xio.ApplyReuse(fd, s, true); err != nil {
		_ = unix.Close(fd)
		return nil, err
	}
	optionNetwork := "sctp4"
	if family == unix.AF_INET6 {
		optionNetwork = "sctp6"
	}
	if err := xio.ApplyNetworkSocketOptions(fd, s, optionNetwork); err != nil {
		_ = unix.Close(fd)
		return nil, err
	}
	if err := xio.ApplyGenericSetsockopt(fd, s, xio.SockoptPhasePrebind); err != nil {
		_ = unix.Close(fd)
		return nil, err
	}
	if family == unix.AF_INET6 {
		v6only := 1
		if network == "sctp" {
			v6only = 0
		}
		if s.HasOption("ipv6-v6only") {
			v6only = 0
			if s.BoolOption("ipv6-v6only") {
				v6only = 1
			}
		}
		if err := unix.SetsockoptInt(fd, unix.IPPROTO_IPV6, unix.IPV6_V6ONLY, v6only); err != nil && s.HasOption("ipv6-v6only") {
			_ = unix.Close(fd)
			return nil, fmt.Errorf("ipv6-v6only: %w", err)
		}
	}
	sa, err := ipPortSockaddr(family, ip, portNum)
	if err != nil {
		logx.CloseErr(unix.Close(fd))
		return nil, err
	}
	if err := unix.Bind(fd, sa); err != nil {
		logx.CloseErr(unix.Close(fd))
		return nil, fmt.Errorf("sctp bind: %w", err)
	}
	backlog := 5
	if v := s.OptionValue("backlog", ""); v != "" {
		n, e := xio.ParseIntAny(v)
		if e != nil || n <= 0 {
			logx.CloseErr(unix.Close(fd))
			return nil, fmt.Errorf("backlog: invalid value %q", v)
		}
		backlog = n
	}
	if err := unix.Listen(fd, backlog); err != nil {
		logx.CloseErr(unix.Close(fd))
		return nil, fmt.Errorf("sctp listen: %w", err)
	}
	return &rawListener{fd: fd, domain: family}, nil
}

func dialSCTPAll(ctx context.Context, network, host, port string, s parse.Spec, g *xio.Global, timeout time.Duration, control func(network, address string, c syscall.RawConn) error) (net.Conn, error) {
	portNum, err := xio.ResolvePortNum(network, port)
	if err != nil {
		return nil, err
	}
	ips, err := xio.ResolveConnectIPs(ctx, network, host, s, g)
	if err != nil {
		return nil, err
	}
	if len(ips) == 0 {
		return nil, fmt.Errorf("no addresses for %s", host)
	}
	bindOpt := s.OptionValue("bind", "")
	sp := s.OptionValue("sourceport", "")
	lowport := s.BoolOption("lowport") && (sp == "" || sp == "0")
	var lastErr error
	for _, ip := range ips {
		af := 2
		if !xio.WantIPv4(network, ip) {
			af = 10
		}
		if g != nil && g.Log != nil {
			g.Log.Noticef("opening connection to AF=%d %s", af, net.JoinHostPort(xio.FormatIPForNetwork(network, ip), fmt.Sprintf("%d", portNum)))
		}
		laddr, skip, err := xio.BindTCPAddrForRemote(ctx, ip, s, bindOpt, sp, network)
		if err != nil {
			lastErr = err
			if g != nil && g.Log != nil {
				g.Log.Warningf("bind: %s", err)
			}
			continue
		}
		if skip {
			lastErr = fmt.Errorf("no bind address with matching address family (%d)", af)
			if g != nil && g.Log != nil {
				g.Log.Warningf("%s", lastErr)
			}
			continue
		}
		raddr := &net.TCPAddr{IP: ip, Port: portNum}
		optionNetwork := "sctp4"
		if !xio.WantIPv4(network, ip) {
			optionNetwork = "sctp6"
		}
		// Merge spec-driven rcvtimeo/sndtimeo with any setsockopt= control.
		c, err := connectSCTP(ctx, network, laddr, raddr, timeout, lowport, g, xio.DialControl(s, optionNetwork, control))
		if err != nil {
			lastErr = err
			if g != nil && g.Log != nil {
				g.Log.Noticef("connect AF=%d %s: %s", af, raddr.String(), err)
			}
			continue
		}
		return c, nil
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("connect %s:%s failed", host, port)
	}
	return nil, lastErr
}

func connectSCTP(ctx context.Context, network string, laddr, raddr *net.TCPAddr, timeout time.Duration, lowport bool, g *xio.Global, control func(network, address string, c syscall.RawConn) error) (net.Conn, error) {
	family := unix.AF_INET
	if !xio.WantIPv4(network, raddr.IP) {
		family = unix.AF_INET6
	}
	fd, err := newSocket(family, unix.SOCK_STREAM, unix.IPPROTO_SCTP)
	if err != nil {
		return nil, fmt.Errorf("sctp socket: %w", err)
	}
	if control != nil {
		if err := control(network, raddr.String(), rawFD(fd)); err != nil {
			logx.CloseErr(unix.Close(fd))
			return nil, err
		}
	}
	if lowport {
		if _, err := bindSCTPLowport(fd, family, laddr, g); err != nil {
			logx.CloseErr(unix.Close(fd))
			return nil, fmt.Errorf("lowport: cannot bind a port in %d-%d: %w", xio.LowportMin, xio.LowportMax, err)
		}
	} else if laddr != nil {
		sa, err := ipPortSockaddr(family, laddr.IP, laddr.Port)
		if err != nil {
			logx.CloseErr(unix.Close(fd))
			return nil, err
		}
		if err := unix.Bind(fd, sa); err != nil {
			logx.CloseErr(unix.Close(fd))
			return nil, fmt.Errorf("sctp bind: %w", err)
		}
	}
	sa, err := ipPortSockaddr(family, raddr.IP, raddr.Port)
	if err != nil {
		logx.CloseErr(unix.Close(fd))
		return nil, err
	}
	cctx := ctx
	var cancel context.CancelFunc
	if timeout > 0 {
		cctx, cancel = context.WithTimeout(ctx, timeout)
		defer cancel()
	}
	if err := connectWithCtx(cctx, fd, sa); err != nil {
		logx.CloseErr(unix.Close(fd))
		return nil, err
	}
	return fileConn(fd, "sctp")
}

func bindSCTPLowport(fd, family int, laddr *net.TCPAddr, g *xio.Global) (int, error) {
	ip := net.IPv4zero
	if family == unix.AF_INET6 {
		ip = net.IPv6zero
	}
	if laddr != nil && laddr.IP != nil {
		ip = laddr.IP
	}
	return xio.FirstAvailableLowport(func(port int) error {
		if g != nil && g.Log != nil {
			af := 2
			if family == unix.AF_INET6 {
				af = 10
			}
			g.Log.Debugf("bind({AF=%d %s:%d}, 16)", af, ip.String(), port)
		}
		sa, err := ipPortSockaddr(family, ip, port)
		if err != nil {
			return err
		}
		return unix.Bind(fd, sa)
	})
}

func connectWithCtx(ctx context.Context, fd int, sa unix.Sockaddr) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	done := make(chan error, 1)
	go func() {
		done <- unix.Connect(fd, sa)
	}()
	select {
	case <-ctx.Done():
		_ = unix.Shutdown(fd, unix.SHUT_RDWR)
		<-done
		return ctx.Err()
	case err := <-done:
		return sctpConnectErr(err, func() error {
			_, e := unix.Getpeername(fd)
			return e
		})
	}
}

// sctpConnectErr maps unix.Connect results. EISCONN is success when the
// association is already up: Go may preempt the blocking connect goroutine
// with SIGURG, and Linux SCTP then reports EISCONN for an established
// socket (seen on GitHub linux-arm64 runners).
func sctpConnectErr(err error, connected func() error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, unix.EISCONN) && connected != nil && connected() == nil {
		return nil
	}
	if errors.Is(err, unix.ECONNREFUSED) {
		// SCTP_SERVICENAME greps "Connection refused" without -i.
		// If test.sh ever switches to grep -i, drop this wrap and the nolint.
		return fmt.Errorf("Connection refused") //nolint:staticcheck // ST1005: classic test.sh needs this exact phrase
	}
	return err
}

func fileConn(fd int, name string) (net.Conn, error) {
	f := os.NewFile(uintptr(fd), name)
	if f == nil {
		logx.CloseErr(unix.Close(fd))
		return nil, fmt.Errorf("sctp: invalid fd")
	}
	c, err := net.FileConn(f)
	_ = f.Close()
	if err != nil {
		return nil, err
	}
	return c, nil
}

func ipPortSockaddr(family int, ip net.IP, port int) (unix.Sockaddr, error) {
	if ip == nil {
		return nil, fmt.Errorf("sctp: empty address")
	}
	if family != unix.AF_INET6 {
		if v4 := ip.To4(); v4 != nil {
			sa := &unix.SockaddrInet4{Port: port}
			copy(sa.Addr[:], v4)
			return sa, nil
		}
		if family == unix.AF_INET {
			return nil, fmt.Errorf("sctp: not IPv4 %s", ip)
		}
	}
	if v4 := ip.To4(); v4 != nil {
		sa := &unix.SockaddrInet6{Port: port}
		sa.Addr[10] = 0xff
		sa.Addr[11] = 0xff
		copy(sa.Addr[12:], v4)
		return sa, nil
	}
	v6 := ip.To16()
	if v6 == nil {
		return nil, fmt.Errorf("sctp: bad address %s", ip)
	}
	sa := &unix.SockaddrInet6{Port: port}
	copy(sa.Addr[:], v6)
	return sa, nil
}

type rawFD int

func (fd rawFD) Control(f func(uintptr)) error {
	f(uintptr(fd))
	return nil
}

func (fd rawFD) Read(func(uintptr) bool) error  { return syscall.EINVAL }
func (fd rawFD) Write(func(uintptr) bool) error { return syscall.EINVAL }
