//go:build linux

package posixmqopen

import (
	"os"
	"runtime"
	"strings"
	"unsafe"

	"golang.org/x/sys/unix"
)

// sysName is the Linux syscall form: glibc strips the POSIX leading '/'.
func sysName(name string) (string, error) {
	if name == "" || name[0] != '/' {
		return "", unix.EINVAL
	}
	rest := name[1:]
	if rest == "" || strings.Contains(rest, "/") {
		return "", unix.EINVAL
	}
	return rest, nil
}

// Kernel struct mq_attr (uapi/linux/mqueue.h).
type mqAttr struct {
	Flags    int
	Maxmsg   int
	Msgsize  int
	Curmsgs  int
	reserved [4]int
}

func mqOpen(name string, oflag int, mode uint32, attr *mqAttr) (int, error) {
	sn, err := sysName(name)
	if err != nil {
		return -1, err
	}
	p, err := unix.BytePtrFromString(sn)
	if err != nil {
		return -1, err
	}
	var ap uintptr
	if attr != nil {
		ap = uintptr(unsafe.Pointer(attr)) // #nosec G103 -- There is no safe standard-library API for those calls
	}
	r1, _, e := unix.Syscall6(unix.SYS_MQ_OPEN, uintptr(unsafe.Pointer(p)), uintptr(oflag), uintptr(mode), ap, 0, 0) // #nosec G103 -- There is no safe standard-library API for those calls
	runtime.KeepAlive(p)
	runtime.KeepAlive(attr)
	if e != 0 {
		return -1, e
	}
	return int(r1), nil
}

func mqUnlink(name string) error {
	sn, err := sysName(name)
	if err != nil {
		return err
	}
	p, err := unix.BytePtrFromString(sn)
	if err != nil {
		return err
	}
	_, _, e := unix.Syscall(unix.SYS_MQ_UNLINK, uintptr(unsafe.Pointer(p)), 0, 0) // #nosec G103 -- There is no safe standard-library API for those calls
	runtime.KeepAlive(p)
	if e != 0 {
		return e
	}
	return nil
}

func mqTimedSend(fd int, msg []byte, prio uint32) error {
	var ptr uintptr
	if len(msg) > 0 {
		ptr = uintptr(unsafe.Pointer(&msg[0])) // #nosec G103 -- There is no safe standard-library API for those calls
	}
	_, _, e := unix.Syscall6(unix.SYS_MQ_TIMEDSEND, uintptr(fd), ptr, uintptr(len(msg)), uintptr(prio), 0, 0)
	runtime.KeepAlive(msg)
	if e != 0 {
		return e
	}
	return nil
}

func mqTimedReceive(fd int, buf []byte, prio *uint32) (int, error) {
	var ptr uintptr
	if len(buf) > 0 {
		ptr = uintptr(unsafe.Pointer(&buf[0])) // #nosec G103 -- There is no safe standard-library API for those calls
	}
	var pp uintptr
	if prio != nil {
		pp = uintptr(unsafe.Pointer(prio)) // #nosec G103 -- There is no safe standard-library API for those calls
	}
	r1, _, e := unix.Syscall6(unix.SYS_MQ_TIMEDRECEIVE, uintptr(fd), ptr, uintptr(len(buf)), pp, 0, 0)
	runtime.KeepAlive(buf)
	runtime.KeepAlive(prio)
	if e != 0 {
		return 0, e
	}
	return int(r1), nil
}

func mqGetattr(fd int, attr *mqAttr) error {
	_, _, e := unix.Syscall(unix.SYS_MQ_GETSETATTR, uintptr(fd), 0, uintptr(unsafe.Pointer(attr))) // #nosec G103 -- There is no safe standard-library API for those calls
	runtime.KeepAlive(attr)
	if e != 0 {
		return e
	}
	return nil
}

func mqClose(fd int) error {
	return unix.Close(fd)
}

func readProcLong(path string) (int64, bool) {
	b, err := os.ReadFile(path) // #nosec G304 -- reads a /proc sysctl path we build, not a user file
	if err != nil {
		return 0, false
	}
	n := int64(0)
	neg := false
	for _, c := range b {
		if c == '-' {
			neg = true
			continue
		}
		if c < '0' || c > '9' {
			break
		}
		n = n*10 + int64(c-'0')
	}
	if neg {
		n = -n
	}
	return n, true
}
