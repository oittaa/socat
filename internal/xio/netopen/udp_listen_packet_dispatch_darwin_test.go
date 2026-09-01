//go:build darwin

package netopen

import (
	"encoding/binary"
	"testing"
	"unsafe"

	"github.com/oittaa/socat/internal/xio"
	"golang.org/x/sys/unix"
)

func TestUDPDispatchConnProcessesQueuedAncillary(t *testing.T) {
	data := make([]byte, 4)
	binary.NativeEndian.PutUint32(data, 42)
	conn := &udpDispatchConn{
		pending: udpForkPacket{
			data: []byte("next"),
			oob:  marshalUDPDispatchCmsg(t, unix.IPPROTO_IP, unix.IP_TTL, data),
		},
		havePending: true,
		g:           &xio.Global{},
		done:        make(chan struct{}),
		packets:     make(chan udpForkPacket),
	}

	buf := make([]byte, 8)
	n, err := conn.Read(buf)
	if err != nil || string(buf[:n]) != "next" {
		t.Fatalf("Read = %q, %v; want next, nil", buf[:n], err)
	}
	if got := conn.g.SessionVars["IP_TTL"]; got != "42" {
		t.Fatalf("queued ancillary IP_TTL = %q, want 42", got)
	}
}

func marshalUDPDispatchCmsg(t *testing.T, level, typ int32, data []byte) []byte {
	t.Helper()
	buf := make([]byte, unix.CmsgSpace(len(data)))
	h := (*unix.Cmsghdr)(unsafe.Pointer(&buf[0]))
	h.Level = level
	h.Type = typ
	h.SetLen(unix.CmsgLen(len(data)))
	copy(buf[unix.CmsgLen(0):unix.CmsgLen(0)+len(data)], data)
	return buf
}
