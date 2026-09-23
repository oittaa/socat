//go:build windows

package xio_test

import (
	"errors"
	"os"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"

	"golang.org/x/sys/windows"
)

// serveHostsAllow returns a hosts.allow path. The first open permits
// 127.0.0.1. A later open does not, so a second tcpwrap check hits hosts.deny.
func serveHostsAllow(t *testing.T) string {
	t.Helper()
	path := `\\.\pipe\socat-tcpwrap-` + strconv.FormatInt(int64(os.Getpid()), 10) + `-` + strconv.FormatUint(pipeSeq.Add(1), 10)
	stop := make(chan struct{})
	var once sync.Once
	finish := func() { once.Do(func() { close(stop) }) }
	ready := make(chan error, 1)
	exited := make(chan struct{})
	go func() {
		defer close(exited)
		payloads := [][]byte{[]byte("socat: 127.0.0.1\n"), []byte("socat: 10.0.0.1\n")}
		var next windows.Handle
		var err error
		next, err = createHostsPipe(path)
		ready <- err
		if err != nil {
			return
		}
		for i, payload := range payloads {
			current := next
			next = 0
			if i+1 < len(payloads) {
				next, err = createHostsPipe(path)
				if err != nil {
					_ = windows.CloseHandle(current)
					return
				}
			}
			if !writeHostsPipe(current, payload, stop) {
				if next != 0 {
					_ = windows.CloseHandle(next)
				}
				return
			}
		}
	}()
	if err := <-ready; err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		finish()
		<-exited
	})
	return path
}

var pipeSeq atomic.Uint64

func createHostsPipe(path string) (windows.Handle, error) {
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return 0, err
	}
	return windows.CreateNamedPipe(
		name,
		windows.PIPE_ACCESS_OUTBOUND,
		windows.PIPE_TYPE_BYTE|windows.PIPE_READMODE_BYTE|windows.PIPE_WAIT,
		windows.PIPE_UNLIMITED_INSTANCES,
		4096,
		4096,
		0,
		nil,
	)
}

func writeHostsPipe(h windows.Handle, payload []byte, stop <-chan struct{}) bool {
	errc := make(chan error, 1)
	go func() {
		errc <- windows.ConnectNamedPipe(h, nil)
	}()
	var closeOnce sync.Once
	closePipe := func() { closeOnce.Do(func() { _ = windows.CloseHandle(h) }) }
	select {
	case <-stop:
		closePipe()
		<-errc
		return false
	case err := <-errc:
		if err != nil && !errors.Is(err, windows.ERROR_PIPE_CONNECTED) {
			closePipe()
			return false
		}
		var wrote uint32
		werr := windows.WriteFile(h, payload, &wrote, nil)
		_ = windows.FlushFileBuffers(h)
		closePipe()
		return werr == nil && wrote == uint32(len(payload))
	}
}
