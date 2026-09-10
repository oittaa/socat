//go:build e2e && linux

package e2e_test

import (
	"bufio"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
)

const tcpListenState = 0x0a

func processListens(pid int, network, addr string) (bool, error) {
	_, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return false, err
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return false, err
	}
	inodes, err := processSocketInodes(pid)
	if err != nil {
		if processGone(err) {
			return false, nil
		}
		return false, err
	}
	if len(inodes) == 0 {
		return false, nil
	}
	files, listenOnly := procNetFiles(network)
	for _, name := range files {
		owners, err := procNetPortInodes(name, port, listenOnly)
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return false, err
		}
		for ino := range owners {
			if _, ok := inodes[ino]; ok {
				return true, nil
			}
		}
	}
	return false, nil
}

func procNetFiles(network string) (files []string, listenOnly bool) {
	if strings.HasPrefix(network, "udp") {
		return []string{"/proc/net/udp", "/proc/net/udp6"}, false
	}
	return []string{"/proc/net/tcp", "/proc/net/tcp6"}, true
}

func processSocketInodes(pid int) (map[uint64]struct{}, error) {
	dir := fmt.Sprintf("/proc/%d/fd", pid)
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	inodes := make(map[uint64]struct{})
	for _, e := range entries {
		target, err := os.Readlink(filepath.Join(dir, e.Name()))
		if err != nil {
			if processGone(err) {
				continue
			}
			continue
		}
		const prefix = "socket:["
		if !strings.HasPrefix(target, prefix) || !strings.HasSuffix(target, "]") {
			continue
		}
		n, err := strconv.ParseUint(target[len(prefix):len(target)-1], 10, 64)
		if err != nil {
			continue
		}
		inodes[n] = struct{}{}
	}
	return inodes, nil
}

func procNetPortInodes(path string, port int, listenOnly bool) (map[uint64]struct{}, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	sc := bufio.NewScanner(f)
	if !sc.Scan() {
		return nil, sc.Err()
	}
	out := make(map[uint64]struct{})
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) < 10 {
			continue
		}
		_, portHex, ok := strings.Cut(fields[1], ":")
		if !ok {
			continue
		}
		p, err := strconv.ParseUint(portHex, 16, 16)
		if err != nil || int(p) != port {
			continue
		}
		if listenOnly {
			st, err := strconv.ParseUint(fields[3], 16, 8)
			if err != nil || st != tcpListenState {
				continue
			}
		}
		ino, err := strconv.ParseUint(fields[9], 10, 64)
		if err != nil {
			continue
		}
		out[ino] = struct{}{}
	}
	return out, sc.Err()
}

func processGone(err error) bool {
	return err != nil && (os.IsNotExist(err) || errors.Is(err, syscall.ESRCH))
}
