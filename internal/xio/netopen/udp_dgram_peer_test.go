package netopen

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/oittaa/socat/internal/xio"
)

func listenUDP4Probe(t *testing.T) net.PacketConn {
	t.Helper()
	pc, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = pc.Close() })
	return pc
}

func openDgramStream(t *testing.T, spec string) (*xio.Opened, *net.UDPAddr) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	t.Cleanup(cancel)
	o, err := xio.OpenChannel(ctx, parseChannel(t, spec), xio.ModeRDWR, useGlobal())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = o.Close() })
	la, ok := o.Stream.(interface{ LocalAddr() net.Addr })
	if !ok {
		t.Fatal("stream has no LocalAddr")
	}
	ua, ok := la.LocalAddr().(*net.UDPAddr)
	if !ok {
		t.Fatalf("local addr %T", la.LocalAddr())
	}
	return o, ua
}

func readDgram(t *testing.T, st io.Reader, timeout time.Duration) (string, error) {
	t.Helper()
	if d, ok := st.(interface{ SetReadDeadline(time.Time) error }); ok {
		_ = d.SetReadDeadline(time.Now().Add(timeout))
	}
	buf := make([]byte, 64)
	n, err := st.Read(buf)
	if err != nil {
		return "", err
	}
	return string(buf[:n]), nil
}

func writeTo(t *testing.T, pc net.PacketConn, payload string, dst *net.UDPAddr) {
	t.Helper()
	if err := pc.SetWriteDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := pc.WriteTo([]byte(payload), dst); err != nil {
		t.Fatal(err)
	}
}

func TestUDP4SendtoIgnoresWrongPeer(t *testing.T) {
	testSendtoIgnoresWrongPeer(t, "UDP4-SENDTO", listenUDP4Probe)
}

func TestUDP4SendtoSourceportBinds(t *testing.T) {
	testSendtoSourceportBinds(t, "UDP4-SENDTO", listenUDP4Probe)
}

func TestUDP4DatagramAcceptsWrongPeerByDefault(t *testing.T) {
	testDatagramAcceptsWrongPeer(t, "UDP4-DATAGRAM", listenUDP4Probe)
}

func TestUDP4DatagramRangeFilter(t *testing.T) {
	testDatagramRangeFilter(t, "UDP4-DATAGRAM", listenUDP4Probe)
}

func TestUDP4DatagramSourceportFilter(t *testing.T) {
	testDatagramSourceportFilter(t, "UDP4-DATAGRAM", listenUDP4Probe)
}

func TestUDP4DatagramTCPWrapFilter(t *testing.T) {
	testDatagramTCPWrapFilter(t, "UDP4-DATAGRAM", listenUDP4Probe)
}

func testSendtoSourceportBinds(t *testing.T, typ string, listen func(*testing.T) net.PacketConn) {
	t.Helper()
	dest := listen(t)
	destPort := dest.LocalAddr().(*net.UDPAddr).Port
	for range 20 {
		tmp := listen(t)
		sp := tmp.LocalAddr().(*net.UDPAddr).Port
		_ = tmp.Close()
		if sp == 0 {
			continue
		}
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		o, err := xio.OpenChannel(ctx, parseChannel(t, typ+":127.0.0.1:"+strconv.Itoa(destPort)+",bind=127.0.0.1,sourceport="+strconv.Itoa(sp)), xio.ModeRDWR, useGlobal())
		if err != nil {
			cancel()
			continue
		}
		t.Cleanup(func() {
			_ = o.Close()
			cancel()
		})
		la, ok := o.Stream.(interface{ LocalAddr() net.Addr })
		if !ok {
			t.Fatal("stream has no LocalAddr")
		}
		ua, ok := la.LocalAddr().(*net.UDPAddr)
		if !ok {
			t.Fatalf("local addr %T", la.LocalAddr())
		}
		if ua.Port != sp {
			t.Fatalf("%s bound local %d, want sourceport %d", typ, ua.Port, sp)
		}
		return
	}
	t.Fatalf("%s could not bind an explicit sourceport", typ)
}

func testSendtoIgnoresWrongPeer(t *testing.T, typ string, listen func(*testing.T) net.PacketConn) {
	t.Helper()
	peer := listen(t)
	peerPort := peer.LocalAddr().(*net.UDPAddr).Port
	st, local := openDgramStream(t, typ+":127.0.0.1:"+strconv.Itoa(peerPort)+",bind=127.0.0.1")
	impostor := listen(t)
	writeTo(t, impostor, "impostor", local)
	writeTo(t, peer, "from-peer", local)
	got, err := readDgram(t, st.Stream, 3*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if got != "from-peer" {
		t.Fatalf("%s read %q, want from-peer (wrong peer must be ignored)", typ, got)
	}
}

func testDatagramAcceptsWrongPeer(t *testing.T, typ string, listen func(*testing.T) net.PacketConn) {
	t.Helper()
	dest := listen(t)
	destPort := dest.LocalAddr().(*net.UDPAddr).Port
	st, local := openDgramStream(t, typ+":127.0.0.1:"+strconv.Itoa(destPort)+",bind=127.0.0.1")
	impostor := listen(t)
	writeTo(t, impostor, "impostor", local)
	got, err := readDgram(t, st.Stream, 3*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if got != "impostor" {
		t.Fatalf("%s default should accept any sender, got %q", typ, got)
	}
}

func testDatagramRangeFilter(t *testing.T, typ string, listen func(*testing.T) net.PacketConn) {
	t.Helper()
	dest := listen(t)
	destPort := dest.LocalAddr().(*net.UDPAddr).Port
	denied, local := openDgramStream(t, typ+":127.0.0.1:"+strconv.Itoa(destPort)+",bind=127.0.0.1,range=10.0.0.0/8")
	impostor := listen(t)
	writeTo(t, impostor, "nope", local)
	if _, err := readDgram(t, denied.Stream, 200*time.Millisecond); err == nil {
		t.Fatalf("%s range=10.0.0.0/8 accepted a 127.0.0.1 sender", typ)
	}

	allowed, localOK := openDgramStream(t, typ+":127.0.0.1:"+strconv.Itoa(destPort)+",bind=127.0.0.1,range=127.0.0.1/32")
	writeTo(t, impostor, "ok-range", localOK)
	got, err := readDgram(t, allowed.Stream, 3*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if got != "ok-range" {
		t.Fatalf("%s range=127.0.0.1/32 got %q", typ, got)
	}
}

func testDatagramSourceportFilter(t *testing.T, typ string, listen func(*testing.T) net.PacketConn) {
	t.Helper()
	occupied := listen(t)
	occupiedPort := occupied.LocalAddr().(*net.UDPAddr).Port
	if occupiedPort == 0 {
		t.Fatal("occupied sourceport is 0")
	}
	dest := listen(t)
	destPort := dest.LocalAddr().(*net.UDPAddr).Port
	// Classic xioopen_udp_datagram consumes sourceport before bind, so an
	// occupied nonzero value must still open. Filtering uses destPort.
	st, local := openDgramStream(t, typ+":127.0.0.1:"+strconv.Itoa(destPort)+",bind=127.0.0.1,sourceport="+strconv.Itoa(occupiedPort))
	if local.Port == occupiedPort {
		t.Fatalf("%s bound local %d; DATAGRAM must not bind sourceport", typ, local.Port)
	}
	impostor := listen(t)
	writeTo(t, impostor, "wrong-port", local)
	writeTo(t, dest, "right-port", local)
	got, err := readDgram(t, st.Stream, 3*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if got != "right-port" {
		t.Fatalf("%s sourceport filter got %q, want right-port", typ, got)
	}
}

func testDatagramTCPWrapFilter(t *testing.T, typ string, listen func(*testing.T) net.PacketConn) {
	t.Helper()
	dir := t.TempDir()
	allow := filepath.Join(dir, "hosts.allow")
	deny := filepath.Join(dir, "hosts.deny")
	if err := os.WriteFile(allow, []byte(""), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(deny, []byte("ALL: ALL\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	dest := listen(t)
	destPort := dest.LocalAddr().(*net.UDPAddr).Port
	st, local := openDgramStream(t, typ+":127.0.0.1:"+strconv.Itoa(destPort)+",bind=127.0.0.1,hosts-allow="+allow+",hosts-deny="+deny)
	impostor := listen(t)
	writeTo(t, impostor, "wrapped", local)
	if _, err := readDgram(t, st.Stream, 200*time.Millisecond); err == nil {
		t.Fatalf("%s tcpwrap deny ALL accepted a packet", typ)
	}
}

func TestLogOrStopPeerFilterUsesSessionContext(t *testing.T) {
	if err := logOrStopPeerFilter(context.Background(), nil, context.DeadlineExceeded); err != nil {
		t.Fatalf("live session with resolver deadline: %v", err)
	}
	if err := logOrStopPeerFilter(context.Background(), nil, context.Canceled); err != nil {
		t.Fatalf("live session with canceled resolver error: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := logOrStopPeerFilter(ctx, nil, fmt.Errorf("range lookup")); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled session: %v", err)
	}
}
