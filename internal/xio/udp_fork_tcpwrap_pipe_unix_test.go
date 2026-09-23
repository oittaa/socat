//go:build linux || darwin

package xio_test

import (
	"os"
	"path/filepath"
	"sync"
	"syscall"
	"testing"
)

// serveHostsAllow returns a hosts.allow path. The first open permits
// 127.0.0.1. A later open does not, so a second tcpwrap check hits hosts.deny.
func serveHostsAllow(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "hosts.allow")
	if err := syscall.Mkfifo(path, 0o644); err != nil {
		t.Fatal(err)
	}
	stop := make(chan struct{})
	var once sync.Once
	finish := func() { once.Do(func() { close(stop) }) }
	exited := make(chan struct{})
	go func() {
		defer close(exited)
		payloads := []string{"socat: 127.0.0.1\n", "socat: 10.0.0.1\n"}
		for _, payload := range payloads {
			if !writeFIFO(path, payload, stop) {
				return
			}
		}
	}()
	t.Cleanup(func() {
		finish()
		<-exited
	})
	return path
}

func writeFIFO(path, payload string, stop <-chan struct{}) bool {
	type result struct {
		f   *os.File
		err error
	}
	ch := make(chan result, 1)
	go func() {
		f, err := os.OpenFile(path, os.O_WRONLY, 0)
		ch <- result{f, err}
	}()
	select {
	case <-stop:
		if r, err := os.Open(path); err == nil {
			_ = r.Close()
		}
		res := <-ch
		if res.f != nil {
			_ = res.f.Close()
		}
		return false
	case res := <-ch:
		if res.err != nil {
			return false
		}
		_, err := res.f.WriteString(payload)
		cerr := res.f.Close()
		return err == nil && cerr == nil
	}
}
