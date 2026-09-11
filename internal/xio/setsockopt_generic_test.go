package xio

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net"
	"strings"
	"testing"

	"github.com/oittaa/socat/internal/addrconfig"
	"github.com/oittaa/socat/internal/parse"
	"github.com/oittaa/socat/internal/relay"
)

func TestParseSockoptBinDecimalAndDalan(t *testing.T) {
	data, singleInt, err := addrconfig.ParseDalan("512", 'i')
	if err != nil || !singleInt || nativeDalanInt(data) != 512 {
		t.Fatalf("512: singleInt=%v n=%d data=%q err=%v", singleInt, nativeDalanInt(data), data, err)
	}
	data, singleInt, err = addrconfig.ParseDalan("i1", 'i')
	if err != nil || !singleInt || nativeDalanInt(data) != 1 {
		t.Fatalf("i1: singleInt=%v n=%d data=%q err=%v", singleInt, nativeDalanInt(data), data, err)
	}
	data, singleInt, err = addrconfig.ParseDalan("x01000000", 'i')
	if err != nil || singleInt || hex.EncodeToString(data) != "01000000" {
		t.Fatalf("hex: singleInt=%v data=%x err=%v", singleInt, data, err)
	}
	if _, _, err := addrconfig.ParseDalan("'ab'", 'i'); err == nil {
		t.Fatal("multi-char dalan quote should fail")
	}
}

func TestDalanHexKeepaliveBytes(t *testing.T) {
	b := make([]byte, 4)
	binary.NativeEndian.PutUint32(b, 1)
	data, singleInt, err := addrconfig.ParseDalan("x"+hex.EncodeToString(b), 'i')
	if err != nil || singleInt || len(data) != 4 {
		t.Fatalf("singleInt=%v data=%x err=%v", singleInt, data, err)
	}
	if binary.NativeEndian.Uint32(data) != 1 {
		t.Fatalf("payload=%x want native int 1", data)
	}
}

func TestDecodeSetsockoptRejectsBadArityAndLevel(t *testing.T) {
	spec, err := parse.ParseSpec("TCP:127.0.0.1:9,setsockopt=1:2")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := decodeAddress(spec); err == nil || !strings.Contains(err.Error(), "level:optname:value") {
		t.Fatalf("arity: err=%v", err)
	}
	spec, err = parse.ParseSpec("TCP:127.0.0.1:9,setsockopt=nope:1:1")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := decodeAddress(spec); err == nil || !strings.Contains(err.Error(), "level") {
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
	err = ApplyTCPConnOpts(mustDecodeAddress(t, spec), a)
	if err == nil || !strings.Contains(err.Error(), "does not expose a socket") {
		t.Fatalf("error=%v want connection does not expose a socket", err)
	}
}

func TestSetupStreamSkipsSetsockoptWithoutSocket(t *testing.T) {
	a, b := net.Pipe()
	t.Cleanup(func() {
		_ = a.Close()
		_ = b.Close()
	})
	spec, err := parse.ParseSpec(fmt.Sprintf("TCP:127.0.0.1:9,setsockopt=%d:%d:1", solSocket, soKeepalive))
	if err != nil {
		t.Fatal(err)
	}
	// Same split as sndbuf-late: SetupStream is a fallback for streams that
	// expose a socket fd. QUIC/WS/UDP-RECVFROM apply CONNECTED on the raw
	// fd first, then wrap a non-syscall.Conn session.
	if _, err := SetupStream(mustDecodeAddress(t, spec), relay.NetStream{Conn: a}); err != nil {
		t.Fatalf("SetupStream on net.Pipe: %v", err)
	}
}

func TestApplyGenericSetsockoptToPacketConnRejectsNonSocket(t *testing.T) {
	spec, err := parse.ParseSpec(fmt.Sprintf("QUIC-LISTEN:0,setsockopt=%d:%d:1", solSocket, soKeepalive))
	if err != nil {
		t.Fatal(err)
	}
	err = ApplyGenericSetsockoptToPacketConn(stubPacketConn{}, mustDecodeAddress(t, spec), SockoptPhaseConnected)
	if err == nil || !strings.Contains(err.Error(), "does not expose a socket") {
		t.Fatalf("error=%v want packet connection does not expose a socket", err)
	}
}

func nativeDalanInt(data []byte) int {
	if len(data) < 4 {
		return 0
	}
	return int(int32(binary.NativeEndian.Uint32(data[:4])))
}
