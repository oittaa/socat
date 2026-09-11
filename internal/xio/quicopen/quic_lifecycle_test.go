package quicopen

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/oittaa/socat/internal/logx"
	"github.com/oittaa/socat/internal/parse"
	"github.com/oittaa/socat/internal/xio"
)

func TestQUICConnectWrapAfterLifecycle(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	port := startListenPIPE(t, ctx, fmt.Sprintf("QUIC-LISTEN:0,reuseaddr,bind=127.0.0.1,fork,verify=0,cert=%s", listenCert(t)))

	var ops []string
	restore := xio.InstallLifecycleSyscallHook(func(op string) {
		ops = append(ops, op)
	})
	t.Cleanup(restore)

	cs, err := parse.ParseSpec(fmt.Sprintf("QUIC:127.0.0.1:%d,verify=0,%s", port, fdLifecycleOption()))
	if err != nil {
		t.Fatal(err)
	}
	o, err := openQUICConnect(ctx, cs, xio.ModeRDWR, &xio.Global{Log: logx.New()})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = o.Close() }()
	if len(ops) == 0 {
		t.Fatal("lifecycle option was not applied on the QUIC packet socket")
	}
	echoRoundtrip(t, o.Stream, []byte("quic-lifecycle"))
}

func TestQUICListenWrapAfterLifecycle(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	var mu sync.Mutex
	var ops []string
	restore := xio.InstallLifecycleSyscallHook(func(op string) {
		mu.Lock()
		ops = append(ops, op)
		mu.Unlock()
	})
	t.Cleanup(restore)

	port := startListenPIPE(t, ctx, fmt.Sprintf("QUIC-LISTEN:0,reuseaddr,bind=127.0.0.1,fork,verify=0,cert=%s,%s", listenCert(t), fdLifecycleOption()))
	mu.Lock()
	if len(ops) == 0 {
		mu.Unlock()
		t.Fatal("lifecycle option was not applied on the listen packet socket")
	}
	applied := append([]string(nil), ops...)
	mu.Unlock()

	cs, err := parse.ParseSpec(fmt.Sprintf("QUIC:127.0.0.1:%d,verify=0", port))
	if err != nil {
		t.Fatal(err)
	}
	cli, err := openQUICConnect(ctx, cs, xio.ModeRDWR, &xio.Global{Log: logx.New()})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = cli.Close() }()
	echoRoundtrip(t, cli.Stream, []byte("listen-wrap"))
	mu.Lock()
	got := append([]string(nil), ops...)
	mu.Unlock()
	if fmt.Sprint(got) != fmt.Sprint(applied) {
		t.Fatalf("listen wrap re-applied lifecycle: before %v after %v", applied, got)
	}
}
