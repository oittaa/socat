package testutil

import (
	"fmt"
	"net"
	"strconv"
	"time"
)

const (
	dynamicPortFirst  = 49152
	dynamicPortCount  = 1 << 14
	dynamicPortStride = 7919
)

func dynamicPort(seed uint64, attempt int) int {
	offset := (int(seed&uint64(dynamicPortCount-1)) + attempt*dynamicPortStride) & (dynamicPortCount - 1)
	return dynamicPortFirst + offset
}

// ListenTCPAndUDP binds TCP and UDP listeners to the same dynamic port.
func ListenTCPAndUDP(ip, suffix string) (tcp net.Listener, udp net.PacketConn, addr string, err error) {
	seed := uint64(time.Now().UnixNano())
	var last error
	for attempt := 0; attempt < dynamicPortCount; attempt++ {
		port := strconv.Itoa(dynamicPort(seed, attempt))
		addr = net.JoinHostPort(ip, port)
		tcp, last = net.Listen("tcp"+suffix, addr)
		if last != nil {
			if !retryableBindError(last) {
				return nil, nil, "", last
			}
			continue
		}
		udp, last = net.ListenPacket("udp"+suffix, addr)
		if last == nil {
			return tcp, udp, addr, nil
		}
		_ = tcp.Close()
		if !retryableBindError(last) {
			return nil, nil, "", last
		}
	}
	return nil, nil, "", fmt.Errorf("listen tcp+udp %s: no common dynamic port: %w", ip, last)
}
