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
		h, err := createHostsPipe(path)
		ready <- err
		if err != nil {
			return
		}
		for i, payload := range payloads {
			if !writeHostsPipe(path, h, payload, stop) {
				return
			}
			if i+1 == len(payloads) {
				return
			}
			h, err = createHostsPipe(path)
			if err != nil {
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

func writeHostsPipe(path string, h windows.Handle, payload []byte, stop <-chan struct{}) bool {
	errc := make(chan error, 1)
	go func() {
		errc <- windows.ConnectNamedPipe(h, nil)
	}()
	var closeOnce sync.Once
	closePipe := func() { closeOnce.Do(func() { _ = windows.CloseHandle(h) }) }
	select {
	case <-stop:
		// CloseHandle waits for ConnectNamedPipe, and that call waits for a
		// client. A reader completes both. If the open misses, leave the
		// pending call alone: closing the handle here does not return.
		client, _ := os.Open(path)
		if client != nil {
			<-errc
			_ = client.Close()
			closePipe()
			return false
		}
		select {
		case <-errc:
			closePipe()
		default:
		}
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
