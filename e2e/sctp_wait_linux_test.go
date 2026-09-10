//go:build e2e && linux

package e2e_test

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

var errNoSCTPProc = errors.New("sctp proc endpoints unavailable")

func waitSCTPTestProcess(p *testProcess, port int, timeout time.Duration) error {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	addr := fmt.Sprintf("127.0.0.1:%d", port)
	pid := 0
	if p != nil && p.cmd != nil && p.cmd.Process != nil {
		pid = p.cmd.Process.Pid
	}
	return waitUntil(ctx, p, func() (bool, error) {
		occupied, err := sctpPortOccupied(addr)
		if err != nil || !occupied {
			return occupied, err
		}
		owns, err := sctpProcessListens(pid, port)
		if errors.Is(err, errNoSCTPProc) {
			owns, err = true, nil
		}
		if err != nil || !owns {
			return owns, err
		}
		if p != nil {
			if _, exited := p.status(); exited {
				return false, processExitedWhileWaiting(p)
			}
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

func sctpPortOccupied(addr string) (bool, error) {
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return false, err
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return false, err
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return false, fmt.Errorf("invalid host %q", addr)
	}
	if v4 := ip.To4(); v4 != nil {
		fd, err := unix.Socket(unix.AF_INET, unix.SOCK_STREAM, unix.IPPROTO_SCTP)
		if err != nil {
			return false, err
		}
		defer unix.Close(fd)
		sa := &unix.SockaddrInet4{Port: port}
		copy(sa.Addr[:], v4)
		if err := unix.Bind(fd, sa); err == nil {
			return false, nil
		}
		return true, nil
	}
	fd, err := unix.Socket(unix.AF_INET6, unix.SOCK_STREAM, unix.IPPROTO_SCTP)
	if err != nil {
		return false, err
	}
	defer unix.Close(fd)
	sa := &unix.SockaddrInet6{Port: port}
	copy(sa.Addr[:], ip.To16())
	if err := unix.Bind(fd, sa); err == nil {
		return false, nil
	}
	return true, nil
}
