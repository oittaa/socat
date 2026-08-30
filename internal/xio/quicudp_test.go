package xio

import (
	"bytes"
	"net"
	"os"
	"strings"
	"sync"
	"testing"

	"github.com/oittaa/socat/internal/logx"
)

func TestHushQUICGoUDPBufferWarningSetsEnvWhenUnset(t *testing.T) {
	t.Setenv(quicGoDisableRecvBufWarn, "true")
	if err := os.Unsetenv(quicGoDisableRecvBufWarn); err != nil {
		t.Fatal(err)
	}
	HushQUICGoUDPBufferWarning()
	if v, ok := os.LookupEnv(quicGoDisableRecvBufWarn); !ok || v != "true" {
		t.Fatalf("env %s=%q ok=%v want true", quicGoDisableRecvBufWarn, v, ok)
	}
}

func TestHushQUICGoUDPBufferWarningKeepsExplicitValue(t *testing.T) {
	t.Setenv(quicGoDisableRecvBufWarn, "false")
	HushQUICGoUDPBufferWarning()
	if v := os.Getenv(quicGoDisableRecvBufWarn); v != "false" {
		t.Fatalf("env %s=%q want false (operator override)", quicGoDisableRecvBufWarn, v)
	}
}

func TestReportQUICUDPBufferCapNoticeWhenSmall(t *testing.T) {
	pc, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = pc.Close() })

	quicUDPBufferWarnOnce = sync.Once{}
	lg := logx.New()
	var buf bytes.Buffer
	lg.SetOutput(&buf)
	lg.SetLevel(logx.Notice)
	ReportQUICUDPBufferCap(pc, lg)

	rcv, snd, err := udpSocketBuffers(pc)
	if err != nil {
		t.Fatal(err)
	}
	msg := buf.String()
	if rcv >= quicDesiredUDPBuffer && snd >= quicDesiredUDPBuffer {
		if strings.Contains(msg, "QUIC UDP buffer") {
			t.Fatalf("notice despite large buffers rcv=%d snd=%d: %s", rcv, snd, msg)
		}
		return
	}
	if !strings.Contains(msg, "QUIC UDP buffer") {
		t.Fatalf("missing notice for small buffers rcv=%d snd=%d; log %q", rcv, snd, msg)
	}
	if strings.Contains(msg, "failed to sufficiently increase") {
		t.Fatalf("stdlib quic-go wording leaked into logx: %s", msg)
	}
}

func TestReportQUICUDPBufferCapDefaultLevelHidesNotice(t *testing.T) {
	pc, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = pc.Close() })

	quicUDPBufferWarnOnce = sync.Once{}
	lg := logx.New()
	var buf bytes.Buffer
	lg.SetOutput(&buf)
	ReportQUICUDPBufferCap(pc, lg)
	if strings.Contains(buf.String(), "QUIC UDP buffer") {
		t.Fatalf("notice printed at default Warning level: %s", buf.String())
	}
}

func TestUDPSocketBuffersPropagatesGetsockoptError(t *testing.T) {
	pc, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	if err := pc.Close(); err != nil {
		t.Fatal(err)
	}
	rcv, snd, err := udpSocketBuffers(pc)
	if err == nil {
		t.Fatalf("closed conn: rcv=%d snd=%d err=nil", rcv, snd)
	}
	if rcv != 0 || snd != 0 {
		t.Fatalf("closed conn leaked sizes rcv=%d snd=%d err=%v", rcv, snd, err)
	}
}
