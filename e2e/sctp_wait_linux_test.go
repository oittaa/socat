//go:build e2e && linux

package e2e_test

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

var errNoSCTPProc = errors.New("sctp proc endpoints unavailable")

func sctpWaitProcAvailable() error {
	_, err := sctpEndpointInodes(0)
	if errors.Is(err, errNoSCTPProc) {
		return err
	}
	return nil
}

func waitSCTPTestProcess(p *testProcess, port int, timeout time.Duration) error {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	if p == nil || p.cmd == nil || p.cmd.Process == nil {
		return fmt.Errorf("listen wait requires a child process")
	}
	pid := p.cmd.Process.Pid
	// SCTP readiness uses /proc inode ownership only. A bind probe can
	// steal the address the child is trying to bind.
	return waitUntil(ctx, p, func() (bool, error) {
		owns, err := sctpProcessListens(pid, port)
		if err != nil || !owns {
			return owns, err
		}
		if _, exited := p.status(); exited {
			return false, processExitedWhileWaiting(p)
		}
		return true, nil
	})
}

func sctpProcessListens(pid, port int) (bool, error) {
	inodes, err := processSocketInodes(pid)
	if err != nil {
		if processGone(err) {
			return false, nil
		}
		return false, err
	}
	owners, err := sctpEndpointInodes(port)
	if err != nil {
		return false, err
	}
	for ino := range owners {
		if _, ok := inodes[ino]; ok {
			return true, nil
		}
	}
	return false, nil
}

func sctpEndpointInodes(port int) (map[uint64]struct{}, error) {
	f, err := os.Open("/proc/net/sctp/eps")
	if err != nil {
		if os.IsNotExist(err) {
			return nil, errNoSCTPProc
		}
		return nil, err
	}
	defer func() { _ = f.Close() }()
	sc := bufio.NewScanner(f)
	if !sc.Scan() {
		return nil, sc.Err()
	}
	header := strings.Fields(sc.Text())
	lportIdx, inodeIdx := -1, -1
	for i, col := range header {
		switch col {
		case "LPORT":
			lportIdx = i
		case "INODE":
			inodeIdx = i
		}
	}
	if lportIdx < 0 || inodeIdx < 0 {
		return nil, errNoSCTPProc
	}
	out := make(map[uint64]struct{})
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if inodeIdx >= len(fields) || lportIdx >= len(fields) {
			continue
		}
		p, err := strconv.Atoi(fields[lportIdx])
		if err != nil || p != port {
			continue
		}
		ino, err := strconv.ParseUint(fields[inodeIdx], 10, 64)
		if err != nil {
			continue
		}
		out[ino] = struct{}{}
	}
	return out, sc.Err()
}
