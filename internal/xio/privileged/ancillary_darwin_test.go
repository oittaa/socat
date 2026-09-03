//go:build privileged && darwin

package privileged_test

import (
	"net"
	"testing"
	"time"

	"github.com/oittaa/socat/internal/parse"
	"github.com/oittaa/socat/internal/testutil"
	"github.com/oittaa/socat/internal/xio"
)

func TestRawIPRecvDstaddrRecvifLiveDarwin(t *testing.T) {
	spec, err := parse.ParseSpec("IP4-RECV:253,ip-recvdstaddr,ip-recvif")
	if err != nil {
		t.Fatal(err)
	}
	lc := net.ListenConfig{Control: xio.ListenControl(spec)}
	pc, err := lc.ListenPacket(t.Context(), "ip4:253", "127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = pc.Close() })

	send, err := net.DialIP("ip4:253", nil, &net.IPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = send.Close() })
	if _, err := send.Write([]byte("hi")); err != nil {
		t.Fatal(err)
	}
	if err := pc.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 64)
	oobBuffer := make([]byte, xio.AncillaryBufferSize)
	ipConn, ok := pc.(*net.IPConn)
	if !ok {
		t.Fatalf("ListenPacket type %T", pc)
	}
	n, oobn, flags, _, err := ipConn.ReadMsgIP(buf, oobBuffer)
	if err != nil {
		t.Fatal(err)
	}
	oob := xio.ControlMessageBytes(oobBuffer, oobn, flags)
	if n == 0 {
		t.Fatal("empty raw IP packet")
	}
	g := &xio.Global{}
	xio.ProcessAncillary(oob, g)
	wantIF := testutil.IPv4LoopbackInterface(t)
	if g.SessionVars["IP_DSTADDR"] != "127.0.0.1" {
		t.Fatalf("IP_DSTADDR=%q want 127.0.0.1 session=%v oob=%d", g.SessionVars["IP_DSTADDR"], g.SessionVars, len(oob))
	}
	if g.SessionVars["IP_IF"] != wantIF {
		t.Fatalf("IP_IF=%q want %q session=%v oob=%d", g.SessionVars["IP_IF"], wantIF, g.SessionVars, len(oob))
	}
}
