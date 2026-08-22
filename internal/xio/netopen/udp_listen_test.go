package netopen

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/oittaa/socat/internal/parse"
)

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
