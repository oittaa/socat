package netopen

import (
	"context"
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/oittaa/socat/internal/logx"
	"github.com/oittaa/socat/internal/parse"
	"github.com/oittaa/socat/internal/xio"
)

func TestUDPRecvfromForkWrapAfterLifecycle(t *testing.T) {
	var ops []string
	restore := xio.InstallLifecycleSyscallHook(func(op string) {
		ops = append(ops, op)
	})
	t.Cleanup(restore)

	o := openForkUDP4Recvfrom(t, fmt.Sprintf("UDP4-RECVFROM:0,bind=127.0.0.1,fork,%s", fdLifecycleOption()))
	if len(ops) == 0 {
		t.Fatal("lifecycle option was not applied on the listen socket")
	}
	applied := append([]string(nil), ops...)

	client := dialUDPListener(t, o.Listener())
	ch := startUDPAccept(o.Listener())
	if _, err := client.Write([]byte("hello")); err != nil {
		t.Fatal(err)
	}
	child := waitUDPAccept(t, ch, 2*time.Second, "recvfrom child")
	st, err := o.WrapDial()(child)
	if err != nil {
		t.Fatalf("WrapDial after lifecycle on owner: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	if fmt.Sprint(ops) != fmt.Sprint(applied) {
		t.Fatalf("WrapDial re-applied lifecycle: before %v after %v", applied, ops)
	}
	got, err := readStreamTimeout(t, st, 2*time.Second)
	if err != nil || got != "hello" {
		t.Fatalf("got %q err=%v want hello", got, err)
	}
}

func TestUDPRecvfromForkChildCloseLeavesParentOpen(t *testing.T) {
	o := openForkUDP4Recvfrom(t, "UDP4-RECVFROM:0,bind=127.0.0.1,fork")
	client := dialUDPListener(t, o.Listener())

	accept1 := startUDPAccept(o.Listener())
	if _, err := client.Write([]byte("one")); err != nil {
		t.Fatal(err)
	}
	child1 := waitUDPAccept(t, accept1, 2*time.Second, "first child")
	st1, err := o.WrapDial()(child1)
	if err != nil {
		t.Fatal(err)
	}
	got, err := readStreamTimeout(t, st1, 2*time.Second)
	if err != nil || got != "one" {
		t.Fatalf("first child got %q err=%v", got, err)
	}
	if _, err := st1.Write([]byte("ack")); err != nil {
		t.Fatal(err)
	}
	if err := st1.Close(); err != nil {
		t.Fatal(err)
	}

	if err := client.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}
	reply := make([]byte, 8)
	n, err := client.Read(reply)
	if err != nil || string(reply[:n]) != "ack" {
		t.Fatalf("reply %q err=%v want ack", reply[:n], err)
	}

	accept2 := startUDPAccept(o.Listener())
	if _, err := client.Write([]byte("two")); err != nil {
		t.Fatal(err)
	}
	child2 := waitUDPAccept(t, accept2, 2*time.Second, "second child")
	st2, err := o.WrapDial()(child2)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st2.Close() })
	got, err = readStreamTimeout(t, st2, 2*time.Second)
	if err != nil || got != "two" {
		t.Fatalf("second child got %q err=%v", got, err)
	}
}

func openForkUDP4Recvfrom(t *testing.T, spec string) *xio.Opened {
	t.Helper()
	parsed, err := parse.ParseSpec(spec)
	if err != nil {
		t.Fatal(err)
	}
	o, err := openUDP4Recvfrom(context.Background(), mustAddr(t, parsed), xio.ModeRDWR, xio.NewSession(xio.Options{BlockSize: 8192}, logx.New()))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = o.Close() })
	if o.Listener() == nil || o.WrapDial() == nil {
		t.Fatal("UDP-RECVFROM,fork did not return a wrapable listener")
	}
	return o
}

func dialUDPListener(t *testing.T, ln net.Listener) *net.UDPConn {
	t.Helper()
	client, err := net.DialUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)}, ln.Addr().(*net.UDPAddr))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close() })
	return client
}
