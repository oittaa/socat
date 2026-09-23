package quicopen

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"testing"
	"time"

	"github.com/quic-go/quic-go"

	"github.com/oittaa/socat/internal/logx"
	"github.com/oittaa/socat/internal/parse"
	"github.com/oittaa/socat/internal/xio"
)

func dialSilentQUIC(t *testing.T, ctx context.Context, addr net.Addr) {
	t.Helper()
	pc, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = pc.Close() })
	tr := &quic.Transport{Conn: pc}
	t.Cleanup(func() { _ = tr.Close() })
	conn, err := tr.Dial(ctx, addr.(*net.UDPAddr), &tls.Config{InsecureSkipVerify: true, NextProtos: []string{defaultALPN}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.CloseWithError(0, "") })
}

func TestQUICAcceptNotBlockedBySilentPeer(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	ch, err := parse.ParseChannel(fmt.Sprintf("QUIC-LISTEN:0,reuseaddr,bind=127.0.0.1,fork,verify=0,cert=%s", listenCert(t)))
	if err != nil {
		t.Fatal(err)
	}
	opened, err := openChannel(ctx, ch, xio.ModeRDWR, xio.NewSession(xio.Options{}, logx.New()))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = opened.Close() })
	ln := opened.Listener()
	dialSilentQUIC(t, ctx, ln.Addr())
	got := make(chan net.Conn, 1)
	go func() {
		if c, err := ln.Accept(); err == nil {
			got <- c
		}
	}()
	spec, err := parse.ParseSpec(fmt.Sprintf("QUIC:%s,verify=0", ln.Addr()))
	if err != nil {
		t.Fatal(err)
	}
	client, err := openQUICConnect(ctx, mustAddr(t, spec), xio.ModeRDWR, &xio.Global{Log: logx.New()})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close() })
	if _, err := io.WriteString(client.Stream(), "x"); err != nil {
		t.Fatal(err)
	}
	select {
	case c := <-got:
		_ = c.SetDeadline(time.Now().Add(time.Second))
		buf := []byte{0}
		if _, err := io.ReadFull(c, buf); err != nil || buf[0] != 'x' {
			t.Fatalf("%q: %v", buf, err)
		}
	case <-ctx.Done():
		t.Fatal("accept blocked on a QUIC peer that opened no stream")
	}
}
