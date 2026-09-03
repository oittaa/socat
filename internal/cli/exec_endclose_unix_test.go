//go:build linux || darwin

package cli

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/oittaa/socat/internal/xio"
)

func TestRunForkListenEndCloseSurvivesNormalExit(t *testing.T) {
	if !xio.FeatureEXEC {
		t.Skip("EXEC not enabled")
	}

	dir := t.TempDir()
	script := filepath.Join(dir, "hold.sh")
	body := "#!/bin/sh\necho $$ >\"" + dir + "/$$\"\nexec sleep 30\n"
	if err := os.WriteFile(script, []byte(body), 0o755); err != nil {
		t.Fatal(err)
	}

	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	if err := ln.Close(); err != nil {
		t.Fatal(err)
	}
	addr := fmt.Sprintf("127.0.0.1:%d", port)

	const children = 32
	args := []string{
		"-t", "0.05",
		fmt.Sprintf("TCP4-LISTEN:%d,reuseaddr,fork,accept-timeout=0.5,bind=127.0.0.1", port),
		fmt.Sprintf("EXEC:%s,end-close,shut-none", script),
	}

	done := make(chan int, 1)
	go func() {
		done <- Run(args, func(int) {})
	}()

	deadline := time.Now().Add(3 * time.Second)
	for i := 0; i < children; i++ {
		var conn net.Conn
		for {
			conn, err = net.DialTimeout("tcp4", addr, 50*time.Millisecond)
			if err == nil {
				break
			}
			if time.Now().After(deadline) {
				t.Fatalf("dial %d/%d: %v", i+1, children, err)
			}
			time.Sleep(5 * time.Millisecond)
		}
		_ = conn.Close()
	}

	pids := waitEndClosePIDFiles(t, dir, children)
	t.Cleanup(func() {
		for _, pid := range pids {
			_ = syscall.Kill(pid, syscall.SIGKILL)
		}
	})

	var code int
	select {
	case code = <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("cli.Run did not return after accept-timeout")
	}
	if code != 0 {
		t.Fatalf("cli.Run exit %d", code)
	}

	var dead []int
	for _, pid := range pids {
		if syscall.Kill(pid, 0) != nil {
			dead = append(dead, pid)
		}
	}
	if len(dead) != 0 {
		t.Fatalf("normal teardown killed %d/%d end-close children: %v", len(dead), len(pids), dead)
	}
}

func waitEndClosePIDFiles(t *testing.T, dir string, want int) []int {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		ents, err := os.ReadDir(dir)
		if err != nil {
			t.Fatal(err)
		}
		var pids []int
		for _, ent := range ents {
			if ent.IsDir() || strings.HasSuffix(ent.Name(), ".sh") {
				continue
			}
			pid, err := strconv.Atoi(ent.Name())
			if err != nil || pid <= 1 {
				continue
			}
			pids = append(pids, pid)
		}
		if len(pids) >= want {
			return pids
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("got fewer than %d EXEC pid files in %s", want, dir)
	return nil
}
