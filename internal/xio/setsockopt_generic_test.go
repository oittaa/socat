package xio

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net"
	"strings"
	"testing"

	"github.com/oittaa/socat/internal/parse"
	"github.com/oittaa/socat/internal/relay"
)

func TestParseSockoptBinDecimalAndDalan(t *testing.T) {
	useInt, n, data, err := parseSockoptBin("512")
	if err != nil || !useInt || n != 512 {
		t.Fatalf("512: useInt=%v n=%d data=%q err=%v", useInt, n, data, err)
	}
	useInt, n, data, err = parseSockoptBin("i1")
	if err != nil || !useInt || n != 1 {
		t.Fatalf("i1: useInt=%v n=%d data=%q err=%v", useInt, n, data, err)
	}
	useInt, n, data, err = parseSockoptBin("x01000000")
	if err != nil || useInt || hex.EncodeToString(data) != "01000000" {
		t.Fatalf("hex: useInt=%v n=%d data=%x err=%v", useInt, n, data, err)
	}
	if _, _, _, err := parseSockoptBin("'ab'"); err == nil {
		t.Fatal("multi-char dalan quote should fail")
	}
}

func TestDalanHexKeepaliveBytes(t *testing.T) {
	b := make([]byte, 4)
	binary.NativeEndian.PutUint32(b, 1)
	useInt, _, data, err := parseSockoptBin("x" + hex.EncodeToString(b))
	if err != nil || useInt || len(data) != 4 {
		t.Fatalf("useInt=%v data=%x err=%v", useInt, data, err)
	}
	if binary.NativeEndian.Uint32(data) != 1 {
		t.Fatalf("payload=%x want native int 1", data)
	}
}

func TestApplySetsockoptFDRejectsBadArityAndLevel(t *testing.T) {
	if err := ApplySetsockoptFD(0, "1:2"); err == nil || !strings.Contains(err.Error(), "level:optname:value") {
		t.Fatalf("arity: err=%v", err)
	}
	if err := ApplySetsockoptFD(0, "nope:1:1"); err == nil || !strings.Contains(err.Error(), "level") {
		t.Fatalf("level: err=%v", err)
	}
}

func TestApplyTCPConnOptsRejectsSetsockoptWithoutSocket(t *testing.T) {
	a, b := net.Pipe()
	t.Cleanup(func() {
		_ = a.Close()
		_ = b.Close()
	})
	spec, err := parse.ParseSpec(fmt.Sprintf("TCP:127.0.0.1:9,setsockopt=%d:%d:1", solSocket, soKeepalive))
	if err != nil {
		t.Fatal(err)
	}
	err = ApplyTCPConnOpts(spec, a)
	if err == nil || !strings.Contains(err.Error(), "does not expose a socket") {
		t.Fatalf("error=%v want connection does not expose a socket", err)
	}
}

func TestWrapCommonSkipsSetsockoptWithoutSocket(t *testing.T) {
	a, b := net.Pipe()
	t.Cleanup(func() {
		_ = a.Close()
		_ = b.Close()
	})
	spec, err := parse.ParseSpec(fmt.Sprintf("TCP:127.0.0.1:9,setsockopt=%d:%d:1", solSocket, soKeepalive))
	if err != nil {
		t.Fatal(err)
	}
	// Same split as sndbuf-late: WrapCommon is a fallback for streams that
	// expose a socket fd. QUIC/WS/UDP-RECVFROM apply CONNECTED on the raw
	// fd first, then wrap a non-syscall.Conn session.
	if _, err := WrapCommon(spec, relay.NetStream{Conn: a}); err != nil {
		t.Fatalf("WrapCommon on net.Pipe: %v", err)
	}
}

func TestApplyGenericSetsockoptToPacketConnRejectsNonSocket(t *testing.T) {
	spec, err := parse.ParseSpec(fmt.Sprintf("QUIC-LISTEN:0,setsockopt=%d:%d:1", solSocket, soKeepalive))
	if err != nil {
		t.Fatal(err)
	}
	err = ApplyGenericSetsockoptToPacketConn(stubPacketConn{}, spec, SockoptPhaseConnected)
	if err == nil || !strings.Contains(err.Error(), "does not expose a socket") {
		t.Fatalf("error=%v want packet connection does not expose a socket", err)
	}
}
