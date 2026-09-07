//go:build darwin

package dtls13

import (
	"fmt"
	"strconv"
	"strings"
	"sync"
	"syscall"

	"golang.org/x/sys/unix"
)

const (
	darwinBigSur  = 20
	darwinSequoia = 24
)

func setUnfragmentedDF(rawConn syscall.RawConn) (bool, error) {
	version, err := darwinKernelMajor()
	if err != nil || version < darwinBigSur {
		return false, err
	}
	var controlErr error
	var disable bool
	if err := rawConn.Control(func(fd uintptr) {
		addr, err := unix.Getsockname(int(fd))
		if err != nil {
			controlErr = fmt.Errorf("getsockname: %w", err)
			return
		}
		switch addr.(type) {
		case *unix.SockaddrInet4:
			controlErr = unix.SetsockoptInt(int(fd), unix.IPPROTO_IP, unix.IP_DONTFRAG, 1)
		case *unix.SockaddrInet6:
			controlErr = unix.SetsockoptInt(int(fd), unix.IPPROTO_IPV6, unix.IPV6_DONTFRAG, 1)
			if version < darwinSequoia {
				v6only, err := unix.GetsockoptInt(int(fd), unix.IPPROTO_IPV6, unix.IPV6_V6ONLY)
				if err != nil {
					controlErr = fmt.Errorf("IPV6_V6ONLY: %w", err)
					return
				}
				disable = v6only == 0
			}
		default:
			controlErr = fmt.Errorf("unknown address type %T", addr)
		}
	}); err != nil {
		return false, err
	}
	if controlErr != nil {
		return false, controlErr
	}
	return !disable, nil
}

var darwinKernelMajor = sync.OnceValues(func() (int, error) {
	uname := &unix.Utsname{}
	if err := unix.Uname(uname); err != nil {
		return 0, err
	}
	release := unix.ByteSliceToString(uname.Release[:])
	before, _, ok := strings.Cut(release, ".")
	if !ok {
		return 0, nil
	}
	return strconv.Atoi(before)
})
