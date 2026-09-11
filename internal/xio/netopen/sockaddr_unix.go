//go:build linux || darwin

package netopen

import (
	"context"
	"fmt"
	"runtime"
	"unsafe"

	"github.com/oittaa/socat/internal/addrconfig"
	"github.com/oittaa/socat/internal/xio"
	"golang.org/x/sys/unix"
)

const sockaddrStorageSize = 128

type socketCall struct {
	domain, typ, proto int
	addr               []byte
}

type rawSockaddr struct {
	buf []byte
}

func preparedSocketConfig(ctx context.Context) (addrconfig.Address, error) {
	config, ok := xio.PreparedConfig(ctx)
	if !ok || config.Network.Kind != addrconfig.AddressKindSocket {
		return addrconfig.Address{}, fmt.Errorf("SOCKET: prepared socket configuration is required")
	}
	return config, nil
}

func socketCallFromConfig(config addrconfig.Address) (socketCall, error) {
	raw := config.Network.RawSocket
	if !raw.Set {
		return socketCall{}, fmt.Errorf("%s requires socket parameters", config.Type)
	}
	call := socketCall{
		domain: raw.Domain,
		typ:    raw.Type,
		proto:  raw.Protocol,
		addr:   append([]byte(nil), raw.Address...),
	}
	if config.Network.ProtocolSet {
		call.domain = config.Network.ProtocolFamily
	}
	if config.Network.SocketType.Set {
		call.typ = config.Network.SocketType.Value
	}
	if config.Network.SocketProtocol.Set {
		call.proto = config.Network.SocketProtocol.Value
	}
	if len(call.addr) == 0 {
		return socketCall{}, fmt.Errorf("%s requires address", config.Type)
	}
	return call, nil
}

func packRawSockaddr(family int, data []byte) (rawSockaddr, error) {
	if len(data) == 0 {
		return rawSockaddr{}, fmt.Errorf("empty socket address")
	}
	if family < 0 || family > sockaddrFamilyMax() {
		return rawSockaddr{}, fmt.Errorf("domain %d out of range", family)
	}
	hdr := sockaddrHeader(family)
	n := len(hdr) + len(data)
	if n > sockaddrStorageSize {
		return rawSockaddr{}, fmt.Errorf("data too long")
	}
	buf := make([]byte, n)
	copy(buf, hdr)
	copy(buf[len(hdr):], data)
	setSockaddrLen(buf)
	return rawSockaddr{buf: buf}, nil
}

func (sa rawSockaddr) withStorage(fn func(ptr unsafe.Pointer, n uintptr) error) error {
	if len(sa.buf) == 0 {
		return fmt.Errorf("empty socket address")
	}
	if len(sa.buf) > sockaddrStorageSize {
		return fmt.Errorf("data too long")
	}
	var storage [sockaddrStorageSize]byte
	copy(storage[:], sa.buf)
	err := fn(unsafe.Pointer(&storage[0]), uintptr(len(sa.buf))) // #nosec G103 -- bind/connect/sendto need the packed bytes and exact length
	runtime.KeepAlive(storage)
	return err
}

func bindRaw(ctx context.Context, fd int, sa rawSockaddr) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	return sa.withStorage(func(ptr unsafe.Pointer, n uintptr) error {
		_, _, errno := unix.Syscall(unix.SYS_BIND, uintptr(fd), uintptr(ptr), n) // #nosec G103 -- bind(2) uses packed sockaddr bytes
		if errno != 0 {
			return errno
		}
		return nil
	})
}

func connectRaw(ctx context.Context, fd int, sa rawSockaddr) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if ctx.Done() == nil {
		return sysConnect(fd, sa)
	}
	if err := unix.SetNonblock(fd, true); err != nil {
		return err
	}
	err := connectInterruptible(ctx, fd, sa)
	if rerr := unix.SetNonblock(fd, false); err == nil {
		err = rerr
	}
	return err
}

func sysConnect(fd int, sa rawSockaddr) error {
	return sa.withStorage(func(ptr unsafe.Pointer, n uintptr) error {
		_, _, errno := unix.Syscall(unix.SYS_CONNECT, uintptr(fd), uintptr(ptr), n) // #nosec G103 -- connect(2) uses packed sockaddr bytes
		if errno != 0 {
			return errno
		}
		return nil
	})
}

func connectInterruptible(ctx context.Context, fd int, sa rawSockaddr) error {
	errno := connectErrno(fd, sa)
	for {
		if errno == 0 {
			return nil
		}
		if errno == unix.EINPROGRESS {
			return waitUnixConnect(ctx, fd)
		}
		if errno != unix.EAGAIN && errno != unix.EWOULDBLOCK {
			return errno
		}
		if err := waitUnixConnectRetry(ctx); err != nil {
			return err
		}
		errno = connectErrno(fd, sa)
	}
}

func connectErrno(fd int, sa rawSockaddr) unix.Errno {
	var out unix.Errno
	_ = sa.withStorage(func(ptr unsafe.Pointer, n uintptr) error {
		_, _, errno := unix.Syscall(unix.SYS_CONNECT, uintptr(fd), uintptr(ptr), n) // #nosec G103 -- connect(2) uses packed sockaddr bytes
		out = errno
		return nil
	})
	return out
}

func sendtoRaw(fd int, p []byte, sa rawSockaddr) error {
	return sa.withStorage(func(ptr unsafe.Pointer, n uintptr) error {
		var pptr unsafe.Pointer
		if len(p) > 0 {
			pptr = unsafe.Pointer(&p[0]) // #nosec G103 -- sendto(2) payload pointer
		}
		_, _, errno := unix.Syscall6(unix.SYS_SENDTO, uintptr(fd), uintptr(pptr), uintptr(len(p)), 0, uintptr(ptr), n) // #nosec G103 -- sendto(2) uses packed sockaddr bytes
		runtime.KeepAlive(p)
		if errno != 0 {
			return errno
		}
		return nil
	})
}

func applySocketOpts(fd int, config addrconfig.Address) error {
	if err := xio.ApplyReuse(fd, config, false); err != nil {
		return err
	}
	if err := xio.ApplySocketOptions(fd, config); err != nil {
		return err
	}
	return xio.ApplyPreparedGenericSetsockopt(fd, config, xio.SockoptPhasePrebind)
}

func newSocket(domain, typ, proto int) (int, error) {
	fd, err := unix.Socket(domain, typ|sockCloexec, proto)
	if err != nil {
		return -1, err
	}
	if sockCloexec == 0 {
		unix.CloseOnExec(fd)
	}
	return fd, nil
}
