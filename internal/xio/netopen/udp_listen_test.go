package netopen

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/oittaa/socat/internal/logx"
	"github.com/oittaa/socat/internal/parse"
	"github.com/oittaa/socat/internal/xio"
)

func TestUDPNonForkAcceptTimeouts(t *testing.T) {
	for _, tc := range []struct {
		name string
		spec string
		open func(context.Context, parse.Spec, xio.Mode, *xio.Global) (*xio.Opened, error)
	}{
		{name: "listen", spec: "UDP4-LISTEN:0,accept-timeout=0.03", open: openUDP4Listen},
		{name: "recvfrom", spec: "UDP4-RECVFROM:0,accept-timeout=0.03", open: openUDP4Recvfrom},
	} {
		t.Run(tc.name, func(t *testing.T) {
			spec, err := parse.ParseSpec(tc.spec)
			if err != nil {
				t.Fatal(err)
			}
			g := &xio.Global{BlockSize: 8192, Log: logx.New()}
			start := time.Now()
			_, err = tc.open(context.Background(), spec, xio.ModeRDWR, g)
			if !errors.Is(err, xio.ErrAcceptTimeout) {
				t.Fatalf("error=%v want ErrAcceptTimeout", err)
			}
			if elapsed := time.Since(start); elapsed > time.Second {
				t.Fatalf("accept timeout took %s", elapsed)
			}
		})
	}
}

func TestUDPForkListenerSurvivesReceiveTimeout(t *testing.T) {
	spec, err := parse.ParseSpec("UDP4-RECVFROM:0,fork,rcvtimeo=0.02")
	if err != nil {
		t.Fatal(err)
	}
	pc, err := listenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)}, spec)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	ln := &udpForkListener{
		pc:         pc,
		network:    "udp4",
		laddr:      pc.LocalAddr().(*net.UDPAddr),
		spec:       spec,
		ctx:        ctx,
		rcvTimeout: 20 * time.Millisecond,
	}
	t.Cleanup(func() {
		cancel()
		_ = ln.Close()
	})

	type acceptResult struct {
		conn net.Conn
		err  error
	}
	accepted := make(chan acceptResult, 1)
	go func() {
		conn, err := ln.Accept()
		accepted <- acceptResult{conn: conn, err: err}
	}()

	// Let more than one receive deadline expire before sending the packet.
	time.Sleep(75 * time.Millisecond)
	client, err := net.DialUDP("udp4", nil, pc.LocalAddr().(*net.UDPAddr))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close() })
	const payload = "after-timeout"
	if _, err := client.Write([]byte(payload)); err != nil {
		t.Fatal(err)
	}

	select {
	case result := <-accepted:
		if result.err != nil {
			t.Fatal(result.err)
		}
		t.Cleanup(func() { _ = result.conn.Close() })
		buf := make([]byte, len(payload))
		if err := result.conn.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
			t.Fatal(err)
		}
		n, err := result.conn.Read(buf)
		if err != nil {
			t.Fatal(err)
		}
		if got := string(buf[:n]); got != payload {
			t.Fatalf("payload=%q want %q", got, payload)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Accept did not survive the receive timeout")
	}
}

func TestUDP4BindIPv6WildcardNormalizes(t *testing.T) {
	g := &xio.Global{BlockSize: 8192, Log: logx.New()}
	ctx := context.Background()
	for _, tc := range []struct {
		name string
		spec string
		open func(context.Context, parse.Spec, xio.Mode, *xio.Global) (*xio.Opened, error)
	}{
		{name: "listen", spec: "UDP4-LISTEN:0,bind=::,reuseaddr,accept-timeout=0.05", open: openUDP4Listen},
		{name: "recvfrom", spec: "UDP4-RECVFROM:0,bind=::,reuseaddr,accept-timeout=0.05", open: openUDP4Recvfrom},
		{name: "sendto", spec: "UDP4-SENDTO:127.0.0.1:9,bind=::", open: openUDP4Sendto},
		{name: "connect", spec: "UDP4:127.0.0.1:9,bind=::", open: openUDP4Connect},
	} {
		t.Run(tc.name, func(t *testing.T) {
			spec, err := parse.ParseSpec(tc.spec)
			if err != nil {
				t.Fatal(err)
			}
			o, err := tc.open(ctx, spec, xio.ModeRDWR, g)
			if tc.name == "listen" || tc.name == "recvfrom" {
				if !errors.Is(err, xio.ErrAcceptTimeout) {
					t.Fatalf("error=%v want ErrAcceptTimeout (bind=:: should normalize to 0.0.0.0)", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("open with bind=::: %v", err)
			}
			t.Cleanup(func() { _ = o.Close() })
		})
	}
}

func TestUDPForkListenerAcceptTimeoutAborts(t *testing.T) {
	spec, err := parse.ParseSpec("UDP4-RECVFROM:0,fork")
	if err != nil {
		t.Fatal(err)
	}
	pc, err := listenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)}, spec)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ln := &udpForkListener{
		pc:            pc,
		network:       "udp4",
		laddr:         pc.LocalAddr().(*net.UDPAddr),
		spec:          spec,
		ctx:           ctx,
		acceptTimeout: 40 * time.Millisecond,
	}
	t.Cleanup(func() { _ = ln.Close() })

	start := time.Now()
	_, err = ln.Accept()
	if err == nil {
		t.Fatal("expected accept timeout")
	}
	if err != xio.ErrAcceptTimeout {
		t.Fatalf("err=%v want xio.ErrAcceptTimeout", err)
	}
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Fatalf("accept-timeout took %s", elapsed)
	}
}
