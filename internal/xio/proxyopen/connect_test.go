package proxyopen

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"github.com/oittaa/socat/internal/logx"
	"github.com/oittaa/socat/internal/parse"
	"github.com/oittaa/socat/internal/xio"
)

func connectEchoHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodConnect {
			http.Error(w, "method", http.StatusMethodNotAllowed)
			return
		}
		w.WriteHeader(http.StatusOK)
		if f, ok := w.(http.Flusher); ok {
			f.Flush()
		}
		buf := make([]byte, 8192)
		for {
			n, err := r.Body.Read(buf)
			if n > 0 {
				if _, werr := w.Write(buf[:n]); werr != nil {
					return
				}
				if f, ok := w.(http.Flusher); ok {
					f.Flush()
				}
			}
			if err != nil {
				return
			}
		}
	})
}

func connectForbidHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "no", http.StatusForbidden)
	})
}

func echoViaPROXY(t *testing.T, spec string) {
	t.Helper()
	s, err := parse.ParseSpec(spec)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	o, err := openProxyConnect(ctx, mustAddr(t, s), xio.ModeRDWR, &xio.Global{Log: logx.New()})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = o.Close() }()
	payload := []byte("proxy-connect-ok")
	if _, err := o.Stream().Write(payload); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len(payload))
	if _, err := io.ReadFull(o.Stream(), got); err != nil {
		t.Fatal(err)
	}
	if string(got) != string(payload) {
		t.Fatalf("got %q", got)
	}
}

func TestH2CONNECTEcho(t *testing.T) {
	srv := httptest.NewUnstartedServer(connectEchoHandler())
	srv.EnableHTTP2 = true
	srv.StartTLS()
	defer srv.Close()
	_, port, err := net.SplitHostPort(srv.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	echoViaPROXY(t, fmt.Sprintf("PROXY:127.0.0.1:127.0.0.1:9,http-version=2,proxyport=%s,verify=0", port))
}

func TestH2CONNECTNon200(t *testing.T) {
	srv := httptest.NewUnstartedServer(connectForbidHandler())
	srv.EnableHTTP2 = true
	srv.StartTLS()
	defer srv.Close()
	_, port, err := net.SplitHostPort(srv.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	s, err := parse.ParseSpec(fmt.Sprintf("PROXY:127.0.0.1:127.0.0.1:9,http-version=2,proxyport=%s,verify=0", port))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := openProxyConnect(ctx, mustAddr(t, s), xio.ModeRDWR, &xio.Global{Log: logx.New()}); err == nil {
		t.Fatal("expected CONNECT failure")
	}
}

func TestH2CONNECTVerifyFail(t *testing.T) {
	srv := httptest.NewUnstartedServer(connectEchoHandler())
	srv.EnableHTTP2 = true
	srv.StartTLS()
	defer srv.Close()
	_, port, err := net.SplitHostPort(srv.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	s, err := parse.ParseSpec(fmt.Sprintf("PROXY:127.0.0.1:127.0.0.1:9,http-version=2,proxyport=%s,verify=1", port))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := openProxyConnect(ctx, mustAddr(t, s), xio.ModeRDWR, &xio.Global{Log: logx.New()}); err == nil {
		t.Fatal("expected verify failure")
	}
}

func TestH2cCONNECTEcho(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := strconv.Itoa(ln.Addr().(*net.TCPAddr).Port)
	var p http.Protocols
	p.SetHTTP1(false)
	p.SetUnencryptedHTTP2(true)
	srv := &http.Server{Handler: connectEchoHandler(), Protocols: &p}
	go func() { _ = srv.Serve(ln) }()
	defer func() { _ = srv.Close() }()

	echoViaPROXY(t, fmt.Sprintf("PROXY:127.0.0.1:127.0.0.1:9,http-version=2,h2c,proxyport=%s", port))
}
