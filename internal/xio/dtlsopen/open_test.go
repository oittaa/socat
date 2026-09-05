package dtlsopen

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/oittaa/socat/internal/dtls13"
	"github.com/oittaa/socat/internal/logx"
	"github.com/oittaa/socat/internal/parse"
	"github.com/oittaa/socat/internal/testcert"
	"github.com/oittaa/socat/internal/xio"
	_ "github.com/oittaa/socat/internal/xio/fileopen"
)

func spec(t *testing.T, value string) parse.Spec {
	t.Helper()
	s, err := parse.ParseSpec(value)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func credentials(t *testing.T) (server, client string) {
	t.Helper()
	dir := t.TempDir()
	ca, err := testcert.NewAuthority("DTLS endpoint CA")
	if err != nil {
		t.Fatal(err)
	}
	caFile := filepath.Join(dir, "ca.pem")
	if err := testcert.WriteCertPEM(caFile, ca.DER); err != nil {
		t.Fatal(err)
	}
	options := make([]string, 2)
	for i, name := range []string{"localhost", "client"} {
		usage := x509.ExtKeyUsageServerAuth
		if i == 1 {
			usage = x509.ExtKeyUsageClientAuth
		}
		leaf, err := ca.Leaf(name, []x509.ExtKeyUsage{usage}, nil, []string{name})
		if err != nil {
			t.Fatal(err)
		}
		cert, key, err := leaf.WriteCertAndKey(dir, name)
		if err != nil {
			t.Fatal(err)
		}
		options[i] = fmt.Sprintf(",cert=%s,key=%s,cafile=%s", cert, key, caFile)
	}
	return options[0], options[1] + ",commonname=localhost"
}

func echoServer(t *testing.T, ctx context.Context, options string) (net.Addr, <-chan error) {
	t.Helper()
	g := &xio.Global{Log: logx.New()}
	o, err := xio.OpenSpec(ctx, spec(t, "DTLS-SERVER:0,bind=127.0.0.1,fork"+options), xio.ModeRDWR, g)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = o.Close() })
	pipe, err := parse.ParseChannel("PIPE")
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- xio.RunOpened(ctx, o, pipe, g) }()
	return o.Listener.Addr(), done
}

func roundtrip(t *testing.T, stream io.ReadWriter, message string) {
	t.Helper()
	if _, err := stream.Write([]byte(message)); err != nil {
		t.Fatal(err)
	}
	buffer := make([]byte, 1024)
	n, err := stream.Read(buffer)
	if err != nil || string(buffer[:n]) != message {
		t.Fatalf("datagram = %q, %v; want %q", buffer[:n], err, message)
	}
}

func TestEndpointsMutualAuthenticationAndFork(t *testing.T) {
	server, client := credentials(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	addr, done := echoServer(t, ctx, server+",commonname=client,alpn=socat,range=127.0.0.1/32")
	for _, alias := range []string{"DTLS", "DTLS-CLIENT", "OPENSSL-DTLS-CONNECT"} {
		g := &xio.Global{Log: logx.New()}
		o, err := xio.OpenSpec(ctx, spec(t, alias+":"+addr.String()+client+",alpn=socat,dtls-mtu=600"), xio.ModeRDWR, g)
		if err != nil {
			t.Fatal(err)
		}
		stop := context.AfterFunc(ctx, func() { _ = o.Close() })
		roundtrip(t, o.Stream, alias)
		roundtrip(t, o.Stream, strings.Repeat("x", 500))
		if g.TLSVars["PROTO_VERSION"] != "DTLSv1.3" || g.TLSVars["X509_COMMONNAME"] != "localhost" {
			t.Errorf("peer metadata = %v", g.TLSVars)
		}
		_ = o.Close()
		stop()
	}
	cancel()
	if err := <-done; err != nil && !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
}

func TestNonForkListenerRemainsUsable(t *testing.T) {
	server, client := credentials(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	bound := make(chan net.Addr, 1)
	restore := xio.SetListenBoundTestHook(func(addr net.Addr) { bound <- addr })
	defer restore()
	type result struct {
		opened *xio.Opened
		err    error
	}
	accepted := make(chan result, 1)
	ss := spec(t, "DTLS-LISTEN:0,bind=127.0.0.1,dtls-migration=0"+server)
	go func() {
		o, err := xio.OpenSpec(ctx, ss, xio.ModeRDWR, nil)
		accepted <- result{o, err}
	}()
	var addr net.Addr
	select {
	case addr = <-bound:
	case r := <-accepted:
		t.Fatalf("listener failed before bind: %v", r.err)
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	o, err := xio.OpenSpec(ctx, spec(t, "DTLS:"+addr.String()+client), xio.ModeRDWR, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = o.Close() }()
	r := <-accepted
	if r.err != nil {
		t.Fatal(r.err)
	}
	defer func() { _ = r.opened.Close() }()
	stop := context.AfterFunc(ctx, func() { _ = r.opened.Close(); _ = o.Close() })
	defer stop()
	if r.opened.Listener != nil {
		t.Fatal("non-fork endpoint did not finish accept")
	}
	if _, err := o.Stream.Write([]byte("one")); err != nil {
		t.Fatal(err)
	}
	if _, err := o.Stream.Write([]byte("two")); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"one", "two"} {
		buffer := make([]byte, 64)
		n, err := r.opened.Stream.Read(buffer)
		if err != nil || string(buffer[:n]) != want {
			t.Fatalf("read = %q, %v; want %q", buffer[:n], err, want)
		}
	}
}

func TestEndpointAuthenticationFailures(t *testing.T) {
	server, client := credentials(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	addr, done := echoServer(t, ctx, server+",alpn=socat")
	for _, options := range []string{
		client + ",commonname=wrong.example,alpn=socat",
		client + ",alpn=other",
		",verify=0,alpn=socat",
	} {
		o, err := xio.OpenSpec(ctx, spec(t, "DTLS:"+addr.String()+options), xio.ModeRDWR, nil)
		if err == nil {
			stop := context.AfterFunc(ctx, func() { _ = o.Close() })
			_, err = o.Stream.Read(make([]byte, 1))
			stop()
			_ = o.Close()
			if err == nil || errors.Is(err, net.ErrClosed) || ctx.Err() != nil {
				t.Fatalf("authentication unexpectedly succeeded: %s", options)
			}
		}
	}
	cancel()
	<-done
}

func TestDTLSConfigurationOptions(t *testing.T) {
	for _, options := range []string{
		"method=DTLS1.2", "max-version=DTLS1.2", "min-version=TLS1.3",
		"dtls-mtu=255", "dtls-mtu=65508", "alpn=",
		"so-rcvtimeo=-1", "rcvtimeo=invalid",
	} {
		if _, err := endpointConfig(spec(t, "DTLS:localhost:443,verify=0,"+options), "localhost", false); err == nil {
			t.Errorf("accepted invalid options %q", options)
		}
	}
	cfg, err := endpointConfig(spec(t, "DTLS:localhost:443,verify=0,min-version=DTLS1.2,max-version=DTLS1.3,dtls-migration=0,handshake-timeout=0"), "localhost", false)
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.DisableMigration || !cfg.DisableHandshakeTimeout {
		t.Fatal("explicit disabled migration/handshake timeout was lost")
	}
}

func TestDTLSHandshakeReceiveTimeout(t *testing.T) {
	peer, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = peer.Close() }()
	for _, option := range []string{"so-rcvtimeo=0.05", "rcvtimeo=0.05,retry=1,interval=0"} {
		t.Run(option, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			o, err := xio.OpenSpec(ctx, spec(t, "DTLS:"+peer.LocalAddr().String()+",verify=0,handshake-timeout=0,"+option), xio.ModeRDWR, nil)
			if o != nil {
				_ = o.Close()
			}
			if !errors.Is(err, dtls13.ErrHandshakeReadTimeout) {
				t.Fatalf("blackhole handshake = %v; want receive timeout", err)
			}
		})
	}
}

func TestDTLSReceiveTimeoutAfterHandshakeIsRetryable(t *testing.T) {
	serverOptions, clientOptions := credentials(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	server, err := xio.OpenSpec(ctx, spec(t, "DTLS-SERVER:0,bind=127.0.0.1,fork,so-rcvtimeo=1"+serverOptions), xio.ModeRDWR, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = server.Close() }()
	client, err := xio.OpenSpec(ctx, spec(t, "DTLS:"+server.Listener.Addr().String()+",so-rcvtimeo=1"+clientOptions), xio.ModeRDWR, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = client.Close() }()
	peer, err := xio.AcceptWithTimeout(ctx, server.Listener, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = peer.Close() }()
	stop := context.AfterFunc(ctx, func() { _ = client.Close(); _ = peer.Close() })
	defer stop()
	buffer := make([]byte, 64)
	for range 2 {
		_, err := client.Stream.Read(buffer)
		var retryable interface{ Retryable() bool }
		if !errors.As(err, &retryable) || !retryable.Retryable() {
			t.Fatalf("idle application read must remain retryable: %v", err)
		}
	}
	if _, err := peer.Write([]byte("after idle reads")); err != nil {
		t.Fatal(err)
	}
	if n, err := client.Stream.Read(buffer); err != nil || string(buffer[:n]) != "after idle reads" {
		t.Fatalf("read after receive timeouts = %q, %v", buffer[:n], err)
	}
}

func TestAcceptTimeoutPreservesAcceptedAssociation(t *testing.T) {
	serverOptions, clientOptions := credentials(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	server, err := xio.OpenSpec(ctx, spec(t, "DTLS-SERVER:0,bind=127.0.0.1,fork"+serverOptions), xio.ModeRDWR, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = server.Close() }()
	client, err := xio.OpenSpec(ctx, spec(t, "DTLS:"+server.Listener.Addr().String()+clientOptions), xio.ModeRDWR, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = client.Close() }()
	connection, err := xio.AcceptWithTimeout(ctx, server.Listener, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = connection.Close() }()
	if _, err := xio.AcceptWithTimeout(ctx, server.Listener, time.Millisecond); !errors.Is(err, xio.ErrAcceptTimeout) {
		t.Fatalf("accept timeout = %v", err)
	}
	if err := connection.SetDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := client.Stream.Write([]byte("still alive")); err != nil {
		t.Fatal(err)
	}
	buffer := make([]byte, 64)
	n, err := connection.Read(buffer)
	if err != nil || string(buffer[:n]) != "still alive" {
		t.Fatalf("accepted association after timeout = %q, %v", buffer[:n], err)
	}
}
