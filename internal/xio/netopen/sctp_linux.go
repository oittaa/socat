//go:build linux

package netopen

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"strconv"
	"syscall"
	"time"

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
	case "sctp6", "sctp":
		family = unix.AF_INET6
		if ip == nil {
			ip = net.IPv6zero
		}
	default:
		if ip != nil && ip.To4() == nil {
			family = unix.AF_INET6
		} else if ip == nil {
			ip = net.IPv4zero
		}
	}
	fd, err := newSocket(family, unix.SOCK_STREAM, unix.IPPROTO_SCTP)
	if err != nil {
		return nil, fmt.Errorf("sctp socket: %w", err)
	}
	xio.ApplyReuse(fd, s, true)
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
		_ = unix.SetsockoptInt(fd, unix.IPPROTO_IPV6, unix.IPV6_V6ONLY, v6only)
	}
	sa, err := ipPortSockaddr(ip, portNum)
	if err != nil {
		unix.Close(fd) // #nosec G104 -- Close on cleanup; the first error is already returned
		return nil, err
	}
	if err := unix.Bind(fd, sa); err != nil {
		unix.Close(fd) // #nosec G104 -- Close on cleanup; the first error is already returned
		return nil, fmt.Errorf("sctp bind: %w", err)
	}
	backlog := 5
	if v := s.OptionValue("backlog", ""); v != "" {
		if n, e := strconv.Atoi(v); e == nil && n > 0 {
			backlog = n
		}
	}
	if err := unix.Listen(fd, backlog); err != nil {
		unix.Close(fd) // #nosec G104 -- Close on cleanup; the first error is already returned
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
	var lastErr error
	for _, ip := range ips {
		af := 2
		if ip.To4() == nil {
			af = 10
		}
		if g != nil && g.Log != nil {
			g.Log.Noticef("opening connection to AF=%d %s", af, net.JoinHostPort(ip.String(), fmt.Sprintf("%d", portNum)))
		}
		laddr, skip, err := xio.BindTCPAddrForRemote(ctx, ip, bindOpt, sp)
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
		c, err := connectSCTP(ctx, network, laddr, raddr, timeout, control)
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

func connectSCTP(ctx context.Context, network string, laddr, raddr *net.TCPAddr, timeout time.Duration, control func(network, address string, c syscall.RawConn) error) (net.Conn, error) {
	family := unix.AF_INET
	if raddr.IP.To4() == nil {
		family = unix.AF_INET6
	}
	fd, err := newSocket(family, unix.SOCK_STREAM, unix.IPPROTO_SCTP)
	if err != nil {
		return nil, fmt.Errorf("sctp socket: %w", err)
	}
	if control != nil {
		if err := control(network, raddr.String(), rawFD(fd)); err != nil {
			unix.Close(fd) // #nosec G104 -- Close on cleanup; the first error is already returned
			return nil, err
		}
	}
	if laddr != nil {
		sa, err := ipPortSockaddr(laddr.IP, laddr.Port)
		if err != nil {
			unix.Close(fd) // #nosec G104 -- Close on cleanup; the first error is already returned
			return nil, err
		}
		if err := unix.Bind(fd, sa); err != nil {
			unix.Close(fd) // #nosec G104 -- Close on cleanup; the first error is already returned
			return nil, fmt.Errorf("sctp bind: %w", err)
		}
	}
	sa, err := ipPortSockaddr(raddr.IP, raddr.Port)
	if err != nil {
		unix.Close(fd) // #nosec G104 -- Close on cleanup; the first error is already returned
		return nil, err
	}
	cctx := ctx
	var cancel context.CancelFunc
	if timeout > 0 {
		cctx, cancel = context.WithTimeout(ctx, timeout)
		defer cancel()
	}
	if err := connectWithCtx(cctx, fd, sa); err != nil {
		unix.Close(fd) // #nosec G104 -- Close on cleanup; the first error is already returned
		return nil, err
	}
	return fileConn(fd, "sctp")
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
		if errors.Is(err, unix.ECONNREFUSED) {
			// Classic test.sh SCTP_SERVICENAME greps this exact phrase.
			return fmt.Errorf("Connection refused")
		}
		return err
	}
}

func fileConn(fd int, name string) (net.Conn, error) {
	f := os.NewFile(uintptr(fd), name)
	if f == nil {
		unix.Close(fd) // #nosec G104 -- Close on cleanup; the first error is already returned
		return nil, fmt.Errorf("sctp: invalid fd")
	}
	c, err := net.FileConn(f)
	_ = f.Close()
	if err != nil {
		return nil, err
	}
	return c, nil
}

func ipPortSockaddr(ip net.IP, port int) (unix.Sockaddr, error) {
	if ip == nil {
		return nil, fmt.Errorf("sctp: empty address")
	}
	if v4 := ip.To4(); v4 != nil {
		sa := &unix.SockaddrInet4{Port: port}
		copy(sa.Addr[:], v4)
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
