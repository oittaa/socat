package netopen

import "net"

// connectUDPPeer associates an already-bound UDP socket with peer, matching
// UDP-LISTEN connecting back to the sender so shutdown(SHUT_WR) is valid.
func connectUDPPeer(c *net.UDPConn, peer *net.UDPAddr) error {
	if c == nil || peer == nil {
		return net.ErrClosed
	}
	raw, err := c.SyscallConn()
	if err != nil {
		return err
	}
	var cerr error
	if err := raw.Control(func(fd uintptr) {
		cerr = connectUDPPeerFD(fd, peer)
	}); err != nil {
		return err
	}
	return cerr
}
