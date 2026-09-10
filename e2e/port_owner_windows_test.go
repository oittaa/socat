//go:build e2e && windows

package e2e_test

import (
	"encoding/binary"
	"net"
	"strconv"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	tcpTableOwnerPIDListener = 3
	udpTableOwnerPID         = 1
	errorInsufficientBuffer  = 122
)

var (
	modiphlpapi             = windows.NewLazySystemDLL("iphlpapi.dll")
	procGetExtendedTcpTable = modiphlpapi.NewProc("GetExtendedTcpTable")
	procGetExtendedUdpTable = modiphlpapi.NewProc("GetExtendedUdpTable")
)

func processListens(pid int, network, addr string) (bool, error) {
	_, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return false, err
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return false, err
	}
	wantPID := uint32(pid)
	if strings.HasPrefix(network, "udp") {
		owns, err := udpTableHasPID(windows.AF_INET, wantPID, port)
		if err != nil || owns {
			return owns, err
		}
		return udpTableHasPID(windows.AF_INET6, wantPID, port)
	}
	owns, err := tcpListenTableHasPID(windows.AF_INET, wantPID, port)
	if err != nil || owns {
		return owns, err
	}
	return tcpListenTableHasPID(windows.AF_INET6, wantPID, port)
}

func tcpListenTableHasPID(family uint32, pid uint32, port int) (bool, error) {
	buf, err := iphlpTable(procGetExtendedTcpTable, family, tcpTableOwnerPIDListener)
	if err != nil {
		return false, err
	}
	if len(buf) < 4 {
		return false, nil
	}
	n := binary.LittleEndian.Uint32(buf[:4])
	off := 4
	if family == windows.AF_INET {
		const rowSize = 24
		for i := uint32(0); i < n && off+rowSize <= len(buf); i++ {
			row := buf[off : off+rowSize]
			localPort := windowsNBOPort(binary.LittleEndian.Uint32(row[8:12]))
			owning := binary.LittleEndian.Uint32(row[20:24])
			if int(localPort) == port && owning == pid {
				return true, nil
			}
			off += rowSize
		}
		return false, nil
	}
	const row6Size = 56
	for i := uint32(0); i < n && off+row6Size <= len(buf); i++ {
		row := buf[off : off+row6Size]
		localPort := windowsNBOPort(binary.LittleEndian.Uint32(row[20:24]))
		owning := binary.LittleEndian.Uint32(row[52:56])
		if int(localPort) == port && owning == pid {
			return true, nil
		}
		off += row6Size
	}
	return false, nil
}

func udpTableHasPID(family uint32, pid uint32, port int) (bool, error) {
	buf, err := iphlpTable(procGetExtendedUdpTable, family, udpTableOwnerPID)
	if err != nil {
		return false, err
	}
	if len(buf) < 4 {
		return false, nil
	}
	n := binary.LittleEndian.Uint32(buf[:4])
	off := 4
	if family == windows.AF_INET {
		const rowSize = 12
		for i := uint32(0); i < n && off+rowSize <= len(buf); i++ {
			row := buf[off : off+rowSize]
			localPort := windowsNBOPort(binary.LittleEndian.Uint32(row[4:8]))
			owning := binary.LittleEndian.Uint32(row[8:12])
			if int(localPort) == port && owning == pid {
				return true, nil
			}
			off += rowSize
		}
		return false, nil
	}
	const row6Size = 28
	for i := uint32(0); i < n && off+row6Size <= len(buf); i++ {
		row := buf[off : off+row6Size]
		localPort := windowsNBOPort(binary.LittleEndian.Uint32(row[20:24]))
		owning := binary.LittleEndian.Uint32(row[24:28])
		if int(localPort) == port && owning == pid {
			return true, nil
		}
		off += row6Size
	}
	return false, nil
}

func iphlpTable(proc *windows.LazyProc, family uint32, class uintptr) ([]byte, error) {
	var size uint32
	r, _, err := proc.Call(0, uintptr(unsafe.Pointer(&size)), 0, uintptr(family), class, 0)
	if r != errorInsufficientBuffer && r != 0 {
		if err != windows.ERROR_INSUFFICIENT_BUFFER && err != windows.Errno(0) {
			return nil, err
		}
	}
	for {
		buf := make([]byte, size)
		r, _, err = proc.Call(uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&size)), 0, uintptr(family), class, 0)
		if r == 0 {
			return buf, nil
		}
		if r == errorInsufficientBuffer {
			continue
		}
		if err != windows.Errno(0) {
			return nil, err
		}
		return nil, windows.Errno(r)
	}
}

func windowsNBOPort(p uint32) uint16 {
	return windows.Ntohs(uint16(p))
}
