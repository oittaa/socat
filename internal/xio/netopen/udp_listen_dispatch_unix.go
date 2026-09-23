//go:build linux || darwin

package netopen

import (
	"errors"
	"fmt"
	"net"

	"github.com/oittaa/socat/internal/xio/sockopt"
	"golang.org/x/sys/unix"
)

func udpForkUsesPeekDial() bool { return true }

// readUDPForkOpener leaves UDP-LISTEN's opener queued until the connected
// child is bound. UDP-RECVFROM remains a consuming, one-shot receive.
func readUDPForkOpener(pc *net.UDPConn, p []byte, wantCtrl bool, oobBuffer []byte, peek bool) (int, []byte, *udpPeer, error) {
	if !peek {
		n, oob, addr, err := sockopt.ReadUDPMsgWithBuffer(pc, p, wantCtrl, oobBuffer)
		return n, oob, udpPeerFromNet(addr), err
	}
	if len(oobBuffer) < sockopt.AncillaryBufferSize && wantCtrl {
		oobBuffer = make([]byte, sockopt.AncillaryBufferSize)
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
	addr, err := udpPeerFromSockaddr(from)
	if err != nil {
		return n, nil, nil, err
	}
	return n, sockopt.ControlMessageBytes(oobBuffer, oobn, flags), addr, nil
}

func readQueuedUDPForkPacket(pc *net.UDPConn, p []byte, wantCtrl bool, oobBuffer []byte) (int, []byte, *udpPeer, bool, error) {
	if len(oobBuffer) < sockopt.AncillaryBufferSize && wantCtrl {
		oobBuffer = make([]byte, sockopt.AncillaryBufferSize)
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
	addr, err := udpPeerFromSockaddr(from)
	if err != nil {
		return n, nil, nil, false, err
	}
	return n, sockopt.ControlMessageBytes(oobBuffer, oobn, flags), addr, true, nil
}

func udpPeerFromSockaddr(sa unix.Sockaddr) (*udpPeer, error) {
	base, ok := packetAddrFromSockaddr(sa).(*net.UDPAddr)
	if !ok {
		return nil, fmt.Errorf("UDP fork opener: unexpected peer address %T", sa)
	}
	peer := &udpPeer{UDPAddr: base}
	in6, ok := sa.(*unix.SockaddrInet6)
	if !ok || in6.ZoneId == 0 {
		return peer, nil
	}
	peer.scope = in6.ZoneId
	peer.Zone = ""
	return peer, nil
}
