package xio

import (
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

// PrepareQUICUDPConn raises the UDP receive/send buffers toward the size
// the QUIC stack wants, then hushes quic-go's standard-log warning so a
// remaining kernel cap is reported through logx (socat format, -d levels).
func PrepareQUICUDPConn(pc net.PacketConn, log *logx.Logger) {
	hushQUICGoUDPBufferWarning()
	if pc == nil {
		return
	}
	raiseQUICUDPBuffers(pc)
	rcv, snd, ok := udpSocketBuffers(pc)
	if !ok {
		return
	}
	if rcv >= quicDesiredUDPBuffer && snd >= quicDesiredUDPBuffer {
		return
	}
	warnQUICUDPBuffers(log, rcv, snd)
}

func hushQUICGoUDPBufferWarning() {
	// wrapConn in quic-go logs via log.Printf unless this env is a truthy
	// bool. Leave an explicit value (including "0"/"false") alone.
	if _, ok := os.LookupEnv(quicGoDisableRecvBufWarn); ok {
		return
	}
	_ = os.Setenv(quicGoDisableRecvBufWarn, "true")
}

func raiseQUICUDPBuffers(pc net.PacketConn) {
	rcv, snd, ok := udpSocketBuffers(pc)
	if c, has := pc.(interface{ SetReadBuffer(int) error }); has {
		if !ok || rcv < quicDesiredUDPBuffer {
			_ = c.SetReadBuffer(quicDesiredUDPBuffer)
		}
	}
	if c, has := pc.(interface{ SetWriteBuffer(int) error }); has {
		if !ok || snd < quicDesiredUDPBuffer {
			_ = c.SetWriteBuffer(quicDesiredUDPBuffer)
		}
	}
	rcv, snd, ok = udpSocketBuffers(pc)
	if ok && rcv >= quicDesiredUDPBuffer && snd >= quicDesiredUDPBuffer {
		return
	}
	forceQUICUDPBuffers(pc, quicDesiredUDPBuffer)
}

func udpSocketBuffers(pc net.PacketConn) (rcv, snd int, ok bool) {
	if pc == nil {
		return 0, 0, false
	}
	sc, ok := pc.(syscall.Conn)
	if !ok {
		return 0, 0, false
	}
	raw, err := sc.SyscallConn()
	if err != nil {
		return 0, 0, false
	}
	if err := raw.Control(func(fd uintptr) {
		rcv, snd = getUDPSocketBuffers(int(fd))
	}); err != nil {
		return 0, 0, false
	}
	return rcv, snd, true
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
