//go:build darwin

package xio

import (
	"io"
	"os"
	"sync"
	"syscall"

	"github.com/oittaa/socat/internal/logx"
	"github.com/oittaa/socat/internal/parse"
	"golang.org/x/sys/unix"
)

const darwinFIONREAD = 0x4004667f

// darwinExecPTYReader keeps the parent's slave open until output queued by an
// exited child has been read. Closing the last slave discards that queue.
type darwinExecPTYReader struct {
	reader    io.Reader
	master    *os.File
	slave     *os.File
	childDone <-chan struct{}
	stop      chan struct{}
	closeOnce sync.Once
}

func execPTYMasterReader(master, slave *os.File, s parse.Spec, childDone <-chan struct{}) (io.Reader, func(), error) {
	r, err := ptyMasterReader(master, s)
	if err != nil {
		logx.CloseQuiet(slave)
		return nil, nil, err
	}
	d := &darwinExecPTYReader{
		reader:    r,
		master:    master,
		slave:     slave,
		childDone: childDone,
		stop:      make(chan struct{}),
	}
	go func() {
		select {
		case <-childDone:
			d.closeSlaveIfDrained()
		case <-d.stop:
		}
	}()
	return d, d.closeSlave, nil
}

func (d *darwinExecPTYReader) Read(p []byte) (int, error) {
	n, err := d.reader.Read(p)
	if n > 0 {
		d.closeSlaveIfDrained()
	}
	return n, err
}

func (d *darwinExecPTYReader) closeSlaveIfDrained() {
	select {
	case <-d.childDone:
	default:
		return
	}
	pending, err := darwinPTYBytesQueued(d.master)
	if err != nil || pending == 0 {
		d.closeSlave()
	}
}

func (d *darwinExecPTYReader) closeSlave() {
	d.closeOnce.Do(func() {
		close(d.stop)
		logx.CloseQuiet(d.slave)
	})
}

func darwinPTYBytesQueued(master *os.File) (int, error) {
	raw, err := master.SyscallConn()
	if err != nil {
		return 0, err
	}
	var pending int
	var ioctlErr error
	controlErr := raw.Control(func(fd uintptr) {
		pending, ioctlErr = unix.IoctlGetInt(int(fd), darwinFIONREAD) // #nosec G115 -- file descriptors fit in int on Darwin
	})
	if controlErr != nil {
		return 0, controlErr
	}
	if ioctlErr != nil {
		return 0, ioctlErr
	}
	return pending, nil
}

func (d *darwinExecPTYReader) SyscallConn() (syscall.RawConn, error) {
	return d.master.SyscallConn()
}

func (d *darwinExecPTYReader) Fd() uintptr { return d.master.Fd() }
