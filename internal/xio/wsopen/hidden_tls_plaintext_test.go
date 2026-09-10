package wsopen

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/oittaa/socat/internal/logx"
	"github.com/oittaa/socat/internal/parse"
	"github.com/oittaa/socat/internal/xio"
)

func assertPlaintextHiddenTLSRejected(t *testing.T, err error, spelling string) {
	t.Helper()
	if err == nil {
		t.Fatal("hidden TLS option opened a plaintext transport")
	}
	msg := err.Error()
	quoted := `"` + spelling + `"`
	if !strings.Contains(msg, quoted) {
		t.Fatalf("missing %s: %v", quoted, err)
	}
	if strings.Contains(msg, "not supported (") {
		t.Fatalf("TLS reject on plaintext: %v", err)
	}
}

func TestWSConnectRejectsFIPS(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	port := wsListenPort(t, startListenPIPE(t, ctx, "WS-LISTEN:0,reuseaddr,bind=127.0.0.1,fork"))
	cs, err := parse.ParseSpec(fmt.Sprintf("WS:127.0.0.1:%d,fips=1", port))
	if err != nil {
		t.Fatal(err)
	}
	o, err := openWSConnect(ctx, cs, xio.ModeRDWR, &xio.Global{Log: logx.New()})
	if o != nil {
		_ = o.Close()
	}
	assertPlaintextHiddenTLSRejected(t, err, "fips")
}

func TestWSListenRejectsFIPS(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	s, err := parse.ParseSpec("WS-LISTEN:0,reuseaddr,bind=127.0.0.1,fips=1")
	if err != nil {
		t.Fatal(err)
	}
	o, err := openWSListen(ctx, s, xio.ModeRDWR, &xio.Global{Log: logx.New()})
	if o != nil {
		_ = o.Close()
	}
	assertPlaintextHiddenTLSRejected(t, err, "fips")
}

func TestWSSConnectRejectsEnabledFIPS(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	cs, err := parse.ParseSpec("WSS:127.0.0.1:1,verify=0,fips=1")
	if err != nil {
		t.Fatal(err)
	}
	_, err = openWSSConnect(ctx, cs, xio.ModeRDWR, &xio.Global{Log: logx.New()})
	if err == nil || !strings.Contains(err.Error(), `"fips"`) || !strings.Contains(err.Error(), "OpenSSL FIPS module") {
		t.Fatalf("%v", err)
	}
}

func TestWSSConnectDisabledFIPSStillEchoes(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	port := wsListenPort(t, startListenPIPE(t, ctx, fmt.Sprintf("WSS-LISTEN:0,reuseaddr,bind=127.0.0.1,fork,verify=0,cert=%s,fips=0", listenCert(t))))
	cs, err := parse.ParseSpec(fmt.Sprintf("WSS:127.0.0.1:%d,verify=0,fips=0", port))
	if err != nil {
		t.Fatal(err)
	}
	o, err := openWSSConnect(ctx, cs, xio.ModeRDWR, &xio.Global{Log: logx.New()})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = o.Close() }()
	echoRoundtrip(t, o.Stream, []byte("wss-fips0"))
}
