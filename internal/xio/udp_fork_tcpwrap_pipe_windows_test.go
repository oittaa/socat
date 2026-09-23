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
		windows.PIPE_ACCESS_OUTBOUND|windows.FILE_FLAG_OVERLAPPED,
		windows.PIPE_TYPE_BYTE|windows.PIPE_READMODE_BYTE|windows.PIPE_WAIT,
		windows.PIPE_UNLIMITED_INSTANCES,
		4096,
		4096,
		0,
		nil,
	)
}

func writeHostsPipe(path string, h windows.Handle, payload []byte, stop <-chan struct{}) bool {
	defer func() { _ = windows.CloseHandle(h) }()
	if !acceptHostsClient(path, h, stop) {
		return false
	}
	return writeHostsPayload(h, payload)
}

func acceptHostsClient(path string, h windows.Handle, stop <-chan struct{}) bool {
	ev, err := windows.CreateEvent(nil, 1, 0, nil)
	if err != nil {
		return false
	}
	defer func() { _ = windows.CloseHandle(ev) }()
	ov := &windows.Overlapped{HEvent: ev}
	err = windows.ConnectNamedPipe(h, ov)
	switch {
	case err == nil || errors.Is(err, windows.ERROR_PIPE_CONNECTED):
		return !stopping(stop)
	case errors.Is(err, windows.ERROR_IO_PENDING):
	default:
		return false
	}
	done := make(chan struct{})
	go func() {
		_, _ = windows.WaitForSingleObject(ev, windows.INFINITE)
		close(done)
	}()
	select {
	case <-stop:
		// Opening the pipe completes ConnectNamedPipe. If that open fails,
		// cancel the pending connect and wait for it before the handle is closed.
		client, oerr := os.Open(path)
		if oerr != nil {
			_ = windows.CancelIoEx(h, ov)
		}
		<-done
		if client != nil {
			_ = client.Close()
		}
		retireOverlapped(h, ov)
		return false
	case <-done:
		return overlappedOK(h, ov)
	}
}

func stopping(stop <-chan struct{}) bool {
	select {
	case <-stop:
		return true
	default:
		return false
	}
}

func retireOverlapped(h windows.Handle, ov *windows.Overlapped) {
	var n uint32
	_ = windows.GetOverlappedResult(h, ov, &n, false)
}

func overlappedOK(h windows.Handle, ov *windows.Overlapped) bool {
	var n uint32
	err := windows.GetOverlappedResult(h, ov, &n, false)
	return err == nil || errors.Is(err, windows.ERROR_PIPE_CONNECTED)
}

func writeHostsPayload(h windows.Handle, payload []byte) bool {
	ev, err := windows.CreateEvent(nil, 1, 0, nil)
	if err != nil {
		return false
	}
	defer func() { _ = windows.CloseHandle(ev) }()
	ov := &windows.Overlapped{HEvent: ev}
	var wrote uint32
	err = windows.WriteFile(h, payload, &wrote, ov)
	if err != nil && !errors.Is(err, windows.ERROR_IO_PENDING) {
		return false
	}
	if err = windows.GetOverlappedResult(h, ov, &wrote, true); err != nil {
		return false
	}
	_ = windows.FlushFileBuffers(h)
	return wrote == uint32(len(payload))
}
