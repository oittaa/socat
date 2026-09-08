//go:build dtlsmeasure

package dtls13

import (
	"bytes"
	"context"
	"crypto/mldsa"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"runtime"
	"testing"
	"time"
)

func TestMeasureLargeHandshake(t *testing.T) {
	for _, parameters := range []struct {
		name string
		make func(*testing.T) (*Config, *Config)
	}{
		{"ECDSA", func(t *testing.T) (*Config, *Config) {
			return handshakeConfigs(t)
		}},
		{"ML-DSA-44", func(t *testing.T) (*Config, *Config) {
			cert, roots := mldsaCertificate(t, mldsa.MLDSA44())
			return pqConfig(cert, roots), pqServerConfig(cert, roots)
		}},
		{"ML-DSA-65", func(t *testing.T) (*Config, *Config) {
			cert, roots := mldsaCertificate(t, mldsa.MLDSA65())
			return pqConfig(cert, roots), pqServerConfig(cert, roots)
		}},
		{"ML-DSA-87", func(t *testing.T) (*Config, *Config) {
			cert, roots := mldsaCertificate(t, mldsa.MLDSA87())
			return pqConfig(cert, roots), pqServerConfig(cert, roots)
		}},
	} {
		for _, mtu := range []int{1200, 512, 256} {
			for _, loss := range []bool{false, true} {
				name := fmt.Sprintf("%s/mtu=%d/loss=%v", parameters.name, mtu, loss)
				t.Run(name+"/inprocess", func(t *testing.T) {
					clientCfg, serverCfg := parameters.make(t)
					clientCfg.MTU, serverCfg.MTU = mtu, mtu
					var mem runtime.MemStats
					runtime.GC()
					runtime.ReadMemStats(&mem)
					alloc0 := mem.TotalAlloc
					cpu0 := time.Now()
					client, server, protocol, jumps, steps, datagrams := driveSessionsMeasured(t, clientCfg, serverCfg, loss)
					cpu := time.Since(cpu0)
					runtime.ReadMemStats(&mem)
					if !client.handshake.complete || !server.handshake.complete {
						t.Fatal("handshake incomplete")
					}
					t.Logf("protocol=%s cpu=%s alloc=%d steps=%d jumps=%d datagrams=%d", protocol, cpu, mem.TotalAlloc-alloc0, steps, jumps, datagrams)
				})
				t.Run(name+"/udp", func(t *testing.T) {
					clientCfg, serverCfg := parameters.make(t)
					clientCfg.MTU, serverCfg.MTU = mtu, mtu
					measureUDPHandshake(t, clientCfg, serverCfg, loss)
				})
			}
		}
	}
}

func pqConfig(cert tls.Certificate, roots *x509.CertPool) *Config {
	return &Config{Certificates: []tls.Certificate{cert}, RootCAs: roots, ServerName: "localhost", CipherSuites: []uint16{chaCha20Poly1305}}
}

func pqServerConfig(cert tls.Certificate, roots *x509.CertPool) *Config {
	return &Config{Certificates: []tls.Certificate{cert}, ClientCAs: roots, ClientAuth: tls.RequireAndVerifyClientCert, CipherSuites: []uint16{chaCha20Poly1305}}
}

func driveSessionsMeasured(t *testing.T, clientConfig, serverConfig *Config, loss bool) (*session, *session, time.Duration, int, int, int) {
	t.Helper()
	var packets []testDatagram
	var client, server *session
	droppedClient, droppedServer, droppedFinal := false, false, false
	sent := 0
	sender := func(fromClient bool) func([]byte) error {
		return func(data []byte) error {
			if loss {
				if fromClient && !droppedClient {
					droppedClient = true
					return nil
				}
				if !fromClient && !droppedServer {
					droppedServer = true
					return nil
				}
				if !fromClient && !droppedFinal && server != nil &&
					(server.handshake.complete || server.outbound != nil && server.outbound.complete) {
					droppedFinal = true
					return nil
				}
			}
			sent++
			packets = append(packets, testDatagram{fromClient, bytes.Clone(data)})
			return nil
		}
	}
	var err error
	start := time.Unix(100, 0)
	now := start
	server, err = newTestServerSession(serverConfig, sender(false))
	if err != nil {
		t.Fatal(err)
	}
	client, err = newClientSession(clientConfig, sender(true), now)
	if err != nil {
		t.Fatal(err)
	}
	timerJumps := 0
	for step := 0; step < 2000; step++ {
		if len(packets) != 0 {
			packet := packets[0]
			packets = packets[1:]
			destination := client
			if packet.fromClient {
				destination = server
			}
			if _, err := destination.receive(packet.data, now); err != nil {
				t.Fatal(err)
			}
			continue
		}
		if client.handshake.complete && server.handshake.complete && client.outbound.complete {
			return client, server, now.Sub(start), timerJumps, step, sent
		}
		next := client.deadline()
		if candidate := server.deadline(); next.IsZero() || !candidate.IsZero() && candidate.Before(next) {
			next = candidate
		}
		if next.IsZero() {
			t.Fatal("handshake stalled")
		}
		if next.After(now) {
			timerJumps++
		}
		now = next
		if err := client.tick(now); err != nil {
			t.Fatal(err)
		}
		if err := server.tick(now); err != nil {
			t.Fatal(err)
		}
	}
	t.Fatal("handshake exceeded bound")
	return nil, nil, 0, 0, 0, 0
}

type countingPacketConn struct {
	net.PacketConn
	sent, recv   int
	sentB, recvB int
}

func (c *countingPacketConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	n, err := c.PacketConn.WriteTo(p, addr)
	if err == nil {
		c.sent++
		c.sentB += n
	}
	return n, err
}

func (c *countingPacketConn) ReadFrom(p []byte) (int, net.Addr, error) {
	n, addr, err := c.PacketConn.ReadFrom(p)
	if err == nil {
		c.recv++
		c.recvB += n
	}
	return n, addr, err
}

type dropFirstHandshake struct {
	net.PacketConn
	remaining int
}

func (c *dropFirstHandshake) WriteTo(p []byte, addr net.Addr) (int, error) {
	if c.remaining > 0 && len(p) > 0 && p[0] == contentHandshake {
		c.remaining--
		return len(p), nil
	}
	return c.PacketConn.WriteTo(p, addr)
}

func measureUDPHandshake(t *testing.T, clientCfg, serverCfg *Config, loss bool) {
	t.Helper()
	serverConn := &countingPacketConn{PacketConn: perfUDP(t)}
	clientConn := &countingPacketConn{PacketConn: perfUDP(t)}
	var clientTransport net.PacketConn = clientConn
	if loss {
		clientTransport = &dropFirstHandshake{PacketConn: clientConn, remaining: 1}
	}
	listener, err := Listen(serverConn, serverCfg)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = listener.Close() }()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	start := time.Now()
	client, err := Client(ctx, clientTransport, listener.Addr(), clientCfg)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = client.Close() }()
	hs := time.Since(start)
	peer, err := listener.AcceptContext(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = peer.Close() }()
	if err := client.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if err := peer.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	echoStart := time.Now()
	if _, err := client.Write([]byte("measure-echo")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 64)
	n, err := peer.Read(buf)
	if err != nil || string(buf[:n]) != "measure-echo" {
		t.Fatalf("server read %q %v", buf[:n], err)
	}
	if _, err := peer.Write(buf[:n]); err != nil {
		t.Fatal(err)
	}
	n, err = client.Read(buf)
	if err != nil || string(buf[:n]) != "measure-echo" {
		t.Fatalf("client echo %q %v", buf[:n], err)
	}
	echo := time.Since(echoStart)
	t.Logf("hs=%s echo=%s client_sent=%d/%dB client_recv=%d/%dB server_sent=%d/%dB",
		hs, echo, clientConn.sent, clientConn.sentB, clientConn.recv, clientConn.recvB, serverConn.sent, serverConn.sentB)
}

func TestMeasureFlightBookkeepingCPU(t *testing.T) {
	body := bytes.Repeat([]byte{1}, 40000)
	f, err := newFlight([]handshakeMessage{{typ: msgCertificate, body: body, epoch: 2}}, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	seq := uint64(0)
	now := time.Unix(1, 0)
	for i := 0; i < 20; i++ {
		if err := f.transmit(now, 200, func(epoch uint64, fragment []byte) (recordNumber, error) {
			seq++
			return recordNumber{epoch, seq}, nil
		}); err != nil {
			t.Fatal(err)
		}
		now = now.Add(time.Second)
	}
	start := time.Now()
	n := 0
	for time.Since(start) < 200*time.Millisecond {
		_ = f.pendingSend()
		_ = f.covered(0, n%len(body))
		n++
	}
	t.Logf("pendingSend+covered calls=%d sent_fragments=%d in %s (%.0f/ms)", n, len(f.sent), time.Since(start), float64(n)/200)
}
