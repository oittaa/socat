//go:build linux || darwin

package netopen

import (
	"errors"
	"fmt"
	"net"
	"strconv"

	"github.com/oittaa/socat/internal/xio"
	"golang.org/x/sys/unix"
)

func newUDPListenForkListener(base *udpForkListener) net.Listener {
	return base
}

func udpForkSharesListenSocket() bool { return false }

func udpForkUsesPeekDial() bool { return true }

// readUDPForkOpener leaves UDP-LISTEN's opener queued until the connected
// child is bound. UDP-RECVFROM remains a consuming, one-shot receive.
func readUDPForkOpener(pc *net.UDPConn, p []byte, wantCtrl bool, oobBuffer []byte, peek bool) (int, []byte, *net.UDPAddr, error) {
	if !peek {
		return xio.ReadUDPMsgWithBuffer(pc, p, wantCtrl, oobBuffer)
	}
	if len(oobBuffer) < xio.AncillaryBufferSize && wantCtrl {
		oobBuffer = make([]byte, xio.AncillaryBufferSize)
	}
	if !wantCtrl {
		oobBuffer = nil
	}

	raw, err := pc.SyscallConn()
	if err != nil {
		return 0, nil, nil, err
	}
	var n, oobn, flags int
	var from unix.Sockaddr
	var recvErr error
	if err := raw.Read(func(fd uintptr) bool {
		for {
			n, oobn, flags, from, recvErr = unix.Recvmsg(int(fd), p, oobBuffer, unix.MSG_PEEK)
			if errors.Is(recvErr, unix.EINTR) {
				continue
			}
			break
		}
		return !errors.Is(recvErr, unix.EAGAIN) && !errors.Is(recvErr, unix.EWOULDBLOCK)
	}); err != nil {
		return 0, nil, nil, err
	}
	if recvErr != nil {
		return n, nil, nil, recvErr
	}
	addr, err := udpAddrFromSockaddr(from)
	if err != nil {
		return n, nil, nil, err
	}
	return n, xio.ControlMessageBytes(oobBuffer, oobn, flags), addr, nil
}

func readQueuedUDPForkPacket(pc *net.UDPConn, p []byte, wantCtrl bool, oobBuffer []byte) (int, []byte, *net.UDPAddr, bool, error) {
	if len(oobBuffer) < xio.AncillaryBufferSize && wantCtrl {
		oobBuffer = make([]byte, xio.AncillaryBufferSize)
	}
	if !wantCtrl {
		oobBuffer = nil
	}

	raw, err := pc.SyscallConn()
	if err != nil {
		return 0, nil, nil, false, err
	}
	var n, oobn, flags int
	var from unix.Sockaddr
	var recvErr error
	if err := raw.Control(func(fd uintptr) {
		for {
			n, oobn, flags, from, recvErr = unix.Recvmsg(int(fd), p, oobBuffer, unix.MSG_DONTWAIT)
			if errors.Is(recvErr, unix.EINTR) {
				continue
			}
			break
		}
	}); err != nil {
		return 0, nil, nil, false, err
	}
	if errors.Is(recvErr, unix.EAGAIN) || errors.Is(recvErr, unix.EWOULDBLOCK) {
		return 0, nil, nil, false, nil
	}
	if recvErr != nil {
		return n, nil, nil, false, recvErr
	}
	addr, err := udpAddrFromSockaddr(from)
	if err != nil {
		return n, nil, nil, false, err
	}
	return n, xio.ControlMessageBytes(oobBuffer, oobn, flags), addr, true, nil
}

func udpAddrFromSockaddr(sa unix.Sockaddr) (*net.UDPAddr, error) {
	addr, ok := packetAddrFromSockaddr(sa).(*net.UDPAddr)
	if !ok {
		return nil, fmt.Errorf("UDP fork opener: unexpected peer address %T", sa)
	}
	if addr.Zone == "" {
		return addr, nil
	}
	index, err := strconv.Atoi(addr.Zone)
	if err != nil {
		return addr, nil
	}
	ifi, err := net.InterfaceByIndex(index)
	if err != nil {
		return nil, fmt.Errorf("UDP fork opener zone %d: %w", index, err)
	}
	addr.Zone = ifi.Name
	return addr, nil
}
