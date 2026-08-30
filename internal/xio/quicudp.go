package xio

import (
	"fmt"
	"net"
	"os"
	"sync"
	"syscall"

	"github.com/oittaa/socat/internal/logx"
)

// quicDesiredUDPBuffer is the kernel UDP socket buffer quic-go v0.61.0
// tries to set (7 MiB receive and send). See
// https://github.com/quic-go/quic-go/wiki/UDP-Buffer-Sizes.
const quicDesiredUDPBuffer = 7 << 20

const quicGoDisableRecvBufWarn = "QUIC_GO_DISABLE_RECEIVE_BUFFER_WARNING"

var quicUDPBufferWarnOnce sync.Once

// HushQUICGoUDPBufferWarning stops quic-go wrapConn from logging via the
// standard log package. Leave an explicit env value (including "0"/"false")
// alone. Call this before Listen or Dial so wrapConn sees the env.
func HushQUICGoUDPBufferWarning() {
	if _, ok := os.LookupEnv(quicGoDisableRecvBufWarn); ok {
		return
	}
	_ = os.Setenv(quicGoDisableRecvBufWarn, "true")
}

// ReportQUICUDPBufferCap inspects the UDP socket after quic-go wrapConn has
// raised SO_RCVBUF/SO_SNDBUF (and Linux SO_RCVBUFFORCE when permitted).
// A remaining shortfall is a kernel cap; log it through logx at notice.
func ReportQUICUDPBufferCap(pc net.PacketConn, log *logx.Logger) {
	if pc == nil {
		return
	}
	rcv, snd, err := udpSocketBuffers(pc)
	if err != nil {
		return
	}
	if rcv >= quicDesiredUDPBuffer && snd >= quicDesiredUDPBuffer {
		return
	}
	warnQUICUDPBuffers(log, rcv, snd)
}

func udpSocketBuffers(pc net.PacketConn) (rcv, snd int, err error) {
	if pc == nil {
		return 0, 0, fmt.Errorf("nil packet conn")
	}
	sc, ok := pc.(syscall.Conn)
	if !ok {
		return 0, 0, fmt.Errorf("packet conn %T does not expose a socket", pc)
	}
	raw, err := sc.SyscallConn()
	if err != nil {
		return 0, 0, err
	}
	var optErr error
	if err := raw.Control(func(fd uintptr) {
		rcv, snd, optErr = getUDPSocketBuffers(int(fd))
	}); err != nil {
		return 0, 0, err
	}
	if optErr != nil {
		return 0, 0, optErr
	}
	return rcv, snd, nil
}

func warnQUICUDPBuffers(log *logx.Logger, rcv, snd int) {
	if log == nil {
		log = logx.Default()
	}
	if log == nil {
		return
	}
	got := rcv
	if snd < got {
		got = snd
	}
	quicUDPBufferWarnOnce.Do(func() {
		log.Noticef("QUIC UDP buffer %d kiB (wanted %d kiB); kernel SO_RCVBUF/SO_SNDBUF cap. See https://github.com/quic-go/quic-go/wiki/UDP-Buffer-Sizes",
			got/1024, quicDesiredUDPBuffer/1024)
	})
}
