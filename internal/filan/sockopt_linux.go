//go:build linux

package filan

import (
	"encoding/binary"

	"github.com/oittaa/socat/internal/outbuf"
	"golang.org/x/sys/unix"
)

func solSocketOpts() []sockopt {
	return []sockopt{
		{unix.SOL_SOCKET, unix.SO_DEBUG, "DEBUG"},
		{unix.SOL_SOCKET, unix.SO_REUSEADDR, "REUSEADDR"},
		{unix.SOL_SOCKET, unix.SO_PROTOCOL, "PROTOCOL"},
		{unix.SOL_SOCKET, unix.SO_TYPE, "TYPE"},
		{unix.SOL_SOCKET, unix.SO_ERROR, "ERROR"},
		{unix.SOL_SOCKET, unix.SO_DONTROUTE, "DONTROUTE"},
		{unix.SOL_SOCKET, unix.SO_BROADCAST, "BROADCAST"},
		{unix.SOL_SOCKET, unix.SO_SNDBUF, "SNDBUF"},
		{unix.SOL_SOCKET, unix.SO_RCVBUF, "RCVBUF"},
		{unix.SOL_SOCKET, unix.SO_KEEPALIVE, "KEEPALIVE"},
		{unix.SOL_SOCKET, unix.SO_OOBINLINE, "OOBINLINE"},
		{unix.SOL_SOCKET, unix.SO_NO_CHECK, "NO_CHECK"},
		{unix.SOL_SOCKET, unix.SO_PRIORITY, "PRIORITY"},
		{unix.SOL_SOCKET, unix.SO_LINGER, "LINGER"},
		{unix.SOL_SOCKET, unix.SO_BSDCOMPAT, "BSDCOMPAT"},
		{unix.SOL_SOCKET, unix.SO_REUSEPORT, "REUSEPORT"},
		{unix.SOL_SOCKET, unix.SO_PASSCRED, "PASSCRED"},
		{unix.SOL_SOCKET, unix.SO_PEERCRED, "PEERCRED"},
		{unix.SOL_SOCKET, unix.SO_RCVLOWAT, "RCVLOWAT"},
		{unix.SOL_SOCKET, unix.SO_SNDLOWAT, "SNDLOWAT"},
		{unix.SOL_SOCKET, unix.SO_RCVTIMEO, "RCVTIMEO"},
		{unix.SOL_SOCKET, unix.SO_SNDTIMEO, "SNDTIMEO"},
		{unix.SOL_SOCKET, unix.SO_SECURITY_AUTHENTICATION, "SECURITY_AUTHENTICATION"},
		{unix.SOL_SOCKET, unix.SO_SECURITY_ENCRYPTION_TRANSPORT, "SECURITY_ENCRYPTION_TRANSPORT"},
		{unix.SOL_SOCKET, unix.SO_SECURITY_ENCRYPTION_NETWORK, "SECURITY_ENCRYPTION_NETWORK"},
		{unix.SOL_SOCKET, unix.SO_BINDTODEVICE, "BINDTODEVICE"},
		{unix.SOL_SOCKET, unix.SO_ATTACH_FILTER, "ATTACH_FILTER"},
		{unix.SOL_SOCKET, unix.SO_DETACH_FILTER, "DETACH_FILTER"},
	}
}

func ipOpts() []sockopt {
	return []sockopt{
		{unix.IPPROTO_IP, unix.IP_TOS, "IP_TOS"},
		{unix.IPPROTO_IP, unix.IP_TTL, "IP_TTL"},
		{unix.IPPROTO_IP, unix.IP_HDRINCL, "IP_HDRINCL"},
		{unix.IPPROTO_IP, unix.IP_OPTIONS, "IP_OPTIONS"},
		{unix.IPPROTO_IP, unix.IP_ROUTER_ALERT, "IP_ROUTER_ALERT"},
		{unix.IPPROTO_IP, unix.IP_RECVOPTS, "IP_RECVOPTS"},
		{unix.IPPROTO_IP, unix.IP_RETOPTS, "IP_RETOPTS"},
		{unix.IPPROTO_IP, unix.IP_PKTINFO, "IP_PKTINFO"},
		{unix.IPPROTO_IP, unix.IP_PKTOPTIONS, "IP_PKTOPTIONS"},
		{unix.IPPROTO_IP, unix.IP_MTU_DISCOVER, "IP_MTU_DISCOVER"},
		{unix.IPPROTO_IP, unix.IP_RECVERR, "IP_RECVERR"},
		{unix.IPPROTO_IP, unix.IP_RECVTTL, "IP_RECVTTL"},
		{unix.IPPROTO_IP, unix.IP_RECVTOS, "IP_RECVTOS"},
		{unix.IPPROTO_IP, unix.IP_TRANSPARENT, "IP_TRANSPARENT"},
		{unix.IPPROTO_IP, unix.IP_MTU, "IP_MTU"},
		{unix.IPPROTO_IP, unix.IP_FREEBIND, "IP_FREEBIND"},
		{unix.IPPROTO_IP, unix.IP_MULTICAST_TTL, "IP_MULTICAST_TTL"},
		{unix.IPPROTO_IP, unix.IP_MULTICAST_LOOP, "IP_MULTICAST_LOOP"},
	}
}

func tcpOpts() []sockopt {
	return []sockopt{
		{unix.IPPROTO_TCP, unix.TCP_NODELAY, "TCP_NODELAY"},
		{unix.IPPROTO_TCP, unix.TCP_MAXSEG, "TCP_MAXSEG"},
		{unix.IPPROTO_TCP, unix.TCP_CORK, "TCP_CORK"},
		{unix.IPPROTO_TCP, unix.TCP_KEEPIDLE, "TCP_KEEPIDLE"},
		{unix.IPPROTO_TCP, unix.TCP_KEEPINTVL, "TCP_KEEPINTVL"},
		{unix.IPPROTO_TCP, unix.TCP_KEEPCNT, "TCP_KEEPCNT"},
		{unix.IPPROTO_TCP, unix.TCP_SYNCNT, "TCP_SYNCNT"},
		{unix.IPPROTO_TCP, unix.TCP_LINGER2, "TCP_LINGER2"},
		{unix.IPPROTO_TCP, unix.TCP_DEFER_ACCEPT, "TCP_ACCEPT"},
		{unix.IPPROTO_TCP, unix.TCP_WINDOW_CLAMP, "TCP_WINDOW_CLAMP"},
		{unix.IPPROTO_TCP, unix.TCP_INFO, "TCP_INFO"},
		{unix.IPPROTO_TCP, unix.TCP_QUICKACK, "TCP_QUICKACK"},
		{unix.IPPROTO_TCP, unix.TCP_MD5SIG, "TCP_MD5SIG"},
	}
}

func printTCPInfoExtra(fd int, b *outbuf.Buf) {
	raw, err := getsockoptBytes(fd, unix.SOL_TCP, unix.TCP_INFO)
	if err != nil || len(raw) < 7 {
		return
	}
	state := uint(raw[0])
	options := uint(raw[5])
	snd, rcv := tcpInfoWscales(raw[6], nativeBigEndian())
	b.Printf("\tTCPI_STATE={%d}\tTCPI_OPTIONS={%d}\tTCPI_SND_WSCALE={%d}\tTCPI_RCV_WSCALE={%d}",
		state, options, snd, rcv)
}

func nativeBigEndian() bool {
	return binary.NativeEndian.Uint16([]byte{0x00, 0x01}) == 1
}

// tcpInfoWscales decodes tcpi_snd_wscale and tcpi_rcv_wscale from the packed
// bitfield byte. GCC allocates the first field in the low nibble on
// little-endian and the high nibble on big-endian.
func tcpInfoWscales(b byte, bigEndian bool) (snd, rcv uint) {
	lo, hi := uint(b&0x0f), uint(b>>4)
	if bigEndian {
		return hi, lo
	}
	return lo, hi
}

// SocketProtocol returns SO_PROTOCOL for fd.
func SocketProtocol(fd int) (int, error) {
	return unix.GetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_PROTOCOL)
}
