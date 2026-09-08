//go:build linux && dtlsinterop

package dtls13

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"os/exec"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestInteropOpenSSLCookieListener(t *testing.T) {
	tools := loadOpenSSLListener(t)
	cert, roots, _, _ := oracleCertificate(t)
	t.Run("classical/1200", func(t *testing.T) {
		testOpenSSLCookieListener(t, tools, cert, roots, tls.X25519, 1200, 0, 0)
	})
	for _, mtu := range []int{1200, 512, 256} {
		t.Run("pq/"+strconv.Itoa(mtu), func(t *testing.T) {
			testOpenSSLCookieListener(t, tools, cert, roots, tls.X25519MLKEM768, mtu, 0, 0)
		})
	}
}

func TestInteropOpenSSLCookieListenerHandshakeLoss(t *testing.T) {
	tools := loadOpenSSLListener(t)
	cert, roots, _, _ := oracleCertificate(t)
	for _, mtu := range []int{1200, 512, 256} {
		t.Run("ch/"+strconv.Itoa(mtu), func(t *testing.T) {
			testOpenSSLCookieListener(t, tools, cert, roots, tls.X25519MLKEM768, mtu, 1, 0)
		})
		t.Run("hrr/"+strconv.Itoa(mtu), func(t *testing.T) {
			testOpenSSLCookieListener(t, tools, cert, roots, tls.X25519MLKEM768, mtu, 0, 1)
		})
	}
}

func loadOpenSSLListener(t *testing.T) oracleTools {
	t.Helper()
	tools := loadOracleTools(t)
	if tools.OpenSSL.Listener == "" {
		t.Fatal("dtlsinterop cookie-listener tests require openssl.listener in SOCAT_DTLS13_TOOLS")
	}
	return tools
}

type capturePacketConn struct {
	net.PacketConn
	mu         sync.Mutex
	sent, recv [][]byte
}

func (c *capturePacketConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	n, err := c.PacketConn.WriteTo(p, addr)
	if err == nil {
		c.mu.Lock()
		c.sent = append(c.sent, bytes.Clone(p[:n]))
		c.mu.Unlock()
	}
	return n, err
}

func (c *capturePacketConn) ReadFrom(p []byte) (int, net.Addr, error) {
	n, addr, err := c.PacketConn.ReadFrom(p)
	if err == nil {
		c.mu.Lock()
		c.recv = append(c.recv, bytes.Clone(p[:n]))
		c.mu.Unlock()
	}
	return n, addr, err
}

func (c *capturePacketConn) snapshot() (sent, recv [][]byte) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return slices.Clone(c.sent), slices.Clone(c.recv)
}

type dropHelloRetry struct {
	net.PacketConn
	remaining int
}

func (c *dropHelloRetry) ReadFrom(p []byte) (int, net.Addr, error) {
	for {
		n, addr, err := c.PacketConn.ReadFrom(p)
		if err != nil || c.remaining == 0 || !isHelloRetryRequest(p[:n]) {
			return n, addr, err
		}
		c.remaining--
	}
}

func testOpenSSLCookieListener(t *testing.T, tools oracleTools, cert tls.Certificate, roots *x509.CertPool, group tls.CurveID, mtu, dropCH, dropHRR int) {
	t.Helper()
	cert, roots, certFile, keyFile := writeOracleCertificate(t, cert, roots)
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	reservation := udpForOracle(t)
	address := reservation.LocalAddr().(*net.UDPAddr)
	if err := reservation.Close(); err != nil {
		t.Fatal(err)
	}
	command := exec.CommandContext(ctx, tools.OpenSSL.Listener,
		"-listen", address.String(),
		"-cert", certFile, "-key", keyFile, "-CAfile", certFile,
		"-mtu", strconv.Itoa(mtu),
		"-groups", oracleGroupName(group),
		"-ciphersuites", tls.CipherSuiteName(chaCha20Poly1305))
	runOracle(t, command)
	captured := &capturePacketConn{PacketConn: udpForOracle(t)}
	var transport net.PacketConn = captured
	if dropHRR > 0 {
		transport = &dropHelloRetry{PacketConn: transport, remaining: dropHRR}
	}
	if dropCH > 0 {
		transport = &dropFirstPlainHandshake{PacketConn: transport, remaining: dropCH}
	}
	t.Cleanup(func() {
		sent, recv := captured.snapshot()
		t.Logf("client UDP sent %s recv %s mtu=%d dropCH=%d dropHRR=%d", summarizeSizes(sizesOf(sent)), summarizeSizes(sizesOf(recv)), mtu, dropCH, dropHRR)
		if t.Failed() {
			t.Logf("sent handshake:\n%s", formatHandshakeDatagrams(sent))
			t.Logf("recv handshake:\n%s", formatHandshakeDatagrams(recv))
		}
	})
	client, err := Client(ctx, transport, address, &Config{
		Certificates:     []tls.Certificate{cert},
		RootCAs:          roots,
		ServerName:       "localhost",
		CipherSuites:     []uint16{chaCha20Poly1305},
		CurvePreferences: []tls.CurveID{group},
		MTU:              mtu,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = client.Close() }()
	if err := client.SetDeadline(time.Now().Add(15 * time.Second)); err != nil {
		t.Fatal(err)
	}
	state := client.ConnectionState()
	if state.Version != version13 || state.CipherSuite != chaCha20Poly1305 || state.CurveID != group || len(state.VerifiedChains) == 0 {
		t.Fatalf("negotiated version=%x suite=%x group=%s chains=%d", state.Version, state.CipherSuite, state.CurveID, len(state.VerifiedChains))
	}
	sent, recv := captured.snapshot()
	requireCookieExchange(t, sent, recv)
	for _, n := range sizesOf(sent) {
		if n > mtu {
			t.Fatalf("sent UDP length %d exceeds MTU %d", n, mtu)
		}
	}
	marker := []byte("openssl-listener-echo\n")
	if _, err := client.Write(marker); err != nil {
		t.Fatal(err)
	}
	buffer := make([]byte, 1024)
	n, err := client.Read(buffer)
	if err != nil || !bytes.Equal(buffer[:n], marker) {
		t.Fatalf("OpenSSL listener echo: %q, %v", buffer[:n], err)
	}
}

func sizesOf(datagrams [][]byte) []int {
	out := make([]int, len(datagrams))
	for i, d := range datagrams {
		out[i] = len(d)
	}
	return out
}

func isHelloRetryRequest(datagram []byte) bool {
	rest := datagram
	for len(rest) > 0 {
		rec, next, err := parseRecord(rest, 0)
		if err != nil {
			return false
		}
		rest = next
		if rec.encrypted || rec.typ != contentHandshake {
			continue
		}
		data := rec.body
		for len(data) > 0 {
			f, restf, err := parseFragment(data)
			if err != nil {
				return false
			}
			data = restf
			if f.typ == msgServerHello && f.offset == 0 && len(f.body) >= 34 && bytes.Equal(f.body[2:34], retryRandom[:]) {
				return true
			}
		}
	}
	return false
}

func plainHandshakeMessages(datagrams [][]byte) []handshakeMessage {
	r := &reassembler{}
	var out []handshakeMessage
	for _, datagram := range datagrams {
		rest := datagram
		for len(rest) > 0 {
			rec, next, err := parseRecord(rest, 0)
			if err != nil {
				break
			}
			rest = next
			if rec.encrypted || rec.typ != contentHandshake {
				continue
			}
			if _, err := r.add(rec.body, rec.number.epoch); err != nil {
				continue
			}
			for {
				m, ok := r.pop()
				if !ok {
					break
				}
				out = append(out, m)
			}
		}
	}
	return out
}

func requireCookieExchange(t *testing.T, sent, recv [][]byte) {
	t.Helper()
	var hrrCookie, chCookie []byte
	var sawCH0, sawCH1 bool
	for _, m := range plainHandshakeMessages(recv) {
		if m.typ != msgServerHello {
			continue
		}
		hello, err := parseServerHello(m.body)
		if err != nil || hello.random != retryRandom {
			continue
		}
		cookie, err := parseCookie(hello.extensions[extCookie])
		if err != nil || len(cookie) == 0 {
			t.Fatalf("HelloRetryRequest without cookie: %v", err)
		}
		hrrCookie = cookie
	}
	for _, m := range plainHandshakeMessages(sent) {
		if m.typ != msgClientHello {
			continue
		}
		hello, err := parseClientHello(m.body)
		if err != nil {
			continue
		}
		offer, err := parseClientOffer(hello)
		if err != nil {
			continue
		}
		switch m.sequence {
		case 0:
			sawCH0 = true
			if len(offer.cookie) != 0 {
				t.Fatal("initial ClientHello carried a cookie")
			}
		case 1:
			sawCH1 = true
			chCookie = offer.cookie
		}
	}
	if !sawCH0 || !sawCH1 || len(hrrCookie) == 0 || !bytes.Equal(hrrCookie, chCookie) {
		t.Fatalf("cookie validation missing ch0=%v ch1=%v hrr=%d ch1cookie=%d equal=%v\nsent:\n%srecv:\n%s",
			sawCH0, sawCH1, len(hrrCookie), len(chCookie), bytes.Equal(hrrCookie, chCookie),
			formatHandshakeDatagrams(sent), formatHandshakeDatagrams(recv))
	}
	t.Logf("cookie-validated HRR/CH1 cookie_len=%d", len(hrrCookie))
}

func formatHandshakeDatagrams(datagrams [][]byte) string {
	var b strings.Builder
	for i, datagram := range datagrams {
		fmt.Fprintf(&b, "d%d len=%d", i, len(datagram))
		rest := datagram
		for len(rest) > 0 {
			rec, next, err := parseRecord(rest, 0)
			if err != nil {
				fmt.Fprintf(&b, " parse=%v", err)
				break
			}
			rest = next
			if rec.encrypted {
				fmt.Fprintf(&b, " enc")
				continue
			}
			fmt.Fprintf(&b, " ct=%d", rec.typ)
			if rec.typ != contentHandshake {
				continue
			}
			data := rec.body
			for len(data) > 0 {
				f, restf, err := parseFragment(data)
				if err != nil {
					fmt.Fprintf(&b, " frag=%v", err)
					break
				}
				data = restf
				fmt.Fprintf(&b, " [hs=%d seq=%d off=%d/%d n=%d]", f.typ, f.sequence, f.offset, f.total, len(f.body))
			}
		}
		b.WriteByte('\n')
	}
	return b.String()
}
