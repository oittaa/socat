//go:build linux

// Built only inside the pinned Pion lab checkout by scripts/dtls13-lab.py.
package main

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"sync"
	"time"

	"github.com/pion/dtls/v3"
	"github.com/pion/dtls/v3/pkg/crypto/ciphersuite"
	"github.com/pion/dtls/v3/pkg/crypto/elliptic"
	"github.com/pion/dtls/v3/pkg/protocol"
)

func main() {
	address := flag.String("listen", "127.0.0.1:0", "UDP listen address")
	connect := flag.String("connect", "", "run a two-datagram client against this address")
	certFile := flag.String("cert", "", "certificate and trust anchor")
	keyFile := flag.String("key", "", "private key")
	mtu := flag.Int("mtu", 0, "DTLS MTU; 0 keeps Pion's default")
	group := flag.String("group", "", "key-exchange group; empty keeps Pion's defaults")
	cipher := flag.String("cipher", "", "TLS 1.3 cipher suite; empty keeps Pion's defaults")
	migrate := flag.Bool("migrate", true, "negotiate CID and RRC")
	flag.Parse()
	cert, err := tls.LoadX509KeyPair(*certFile, *keyFile)
	if err != nil {
		log.Fatal(err)
	}
	pem, err := os.ReadFile(*certFile)
	if err != nil {
		log.Fatal(err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(pem) {
		log.Fatal("no trust anchor")
	}
	if *connect != "" {
		runClient(*connect, cert, roots, *mtu, *group, *cipher, *migrate)
		return
	}
	addr, err := net.ResolveUDPAddr("udp4", *address)
	if err != nil {
		log.Fatal(err)
	}
	opts := pionOptions(cert, roots, "", *mtu, *group, *cipher, *migrate, true)
	listener, err := dtls.ListenAddr("udp4", addr, opts...)
	if err != nil {
		log.Fatal(err)
	}
	defer listener.Close()
	fmt.Println("ready", listener.Addr())
	connection, err := listener.Accept()
	if err != nil {
		log.Fatal(err)
	}
	defer connection.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	if err := connection.(*dtls.Conn).HandshakeContext(ctx); err != nil {
		log.Fatal(err)
	}
	if err := connection.SetDeadline(time.Now().Add(20 * time.Second)); err != nil {
		log.Fatal(err)
	}
	buffer := make([]byte, 16384)
	for {
		n, err := connection.Read(buffer)
		if err != nil {
			log.Fatal(err)
		}
		if _, err := connection.Write(buffer[:n]); err != nil {
			log.Fatal(err)
		}
	}
}

func pionOptions(cert tls.Certificate, roots *x509.CertPool, serverName string, mtu int, group, cipher string, migrate, server bool) []dtls.Option {
	opts := []dtls.Option{
		dtls.WithCertificates(cert),
		dtls.WithMinVersion(protocol.Version1_3),
		dtls.WithMaxVersion(protocol.Version1_3),
	}
	if server {
		opts = append(opts, dtls.WithClientCAs(roots), dtls.WithClientAuth(dtls.RequireAndVerifyClientCert))
	} else {
		opts = append(opts, dtls.WithRootCAs(roots), dtls.WithServerName(serverName))
	}
	if mtu > 0 {
		opts = append(opts, dtls.WithMTU(mtu))
	}
	if group != "" {
		opts = append(opts, dtls.WithEllipticCurves(pionGroup(group)))
	}
	if cipher != "" {
		opts = append(opts, dtls.WithCipherSuites(pionCipher(cipher)))
	}
	if migrate {
		opts = append(opts, dtls.WithConnectionID(func() []byte {
			id := make([]byte, 8)
			if _, err := rand.Read(id); err != nil {
				log.Fatal(err)
			}
			return id
		}, dtls.CIDPathMigrationRRC))
	}
	return opts
}

func pionGroup(name string) elliptic.Curve {
	switch name {
	case "X25519MLKEM768":
		return elliptic.X25519MLKEM768
	case "X25519":
		return elliptic.X25519
	case "P-256":
		return elliptic.P256
	default:
		log.Fatalf("unsupported group %q", name)
		return 0
	}
}

func pionCipher(name string) ciphersuite.ID {
	switch name {
	case "TLS_CHACHA20_POLY1305_SHA256":
		return ciphersuite.TLS_CHACHA20_POLY1305_SHA256
	case "TLS_AES_128_GCM_SHA256":
		return ciphersuite.TLS_AES_128_GCM_SHA256
	case "TLS_AES_256_GCM_SHA384":
		return ciphersuite.TLS_AES_256_GCM_SHA384
	default:
		log.Fatalf("unsupported cipher %q", name)
		return 0
	}
}

func runClient(address string, cert tls.Certificate, roots *x509.CertPool, mtu int, group, cipher string, migrate bool) {
	peer, err := net.ResolveUDPAddr("udp4", address)
	if err != nil {
		log.Fatal(err)
	}
	socket, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		log.Fatal(err)
	}
	transport := &rebindPacketConn{PacketConn: socket}
	connection, err := dtls.Client(transport, peer, pionOptions(cert, roots, "localhost", mtu, group, cipher, migrate, false)...)
	if err != nil {
		log.Fatal(err)
	}
	defer connection.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	if err := connection.HandshakeContext(ctx); err != nil {
		log.Fatal(err)
	}
	if err := connection.SetDeadline(time.Now().Add(15 * time.Second)); err != nil {
		log.Fatal(err)
	}
	messages := []string{"pion-pq-echo"}
	if migrate {
		messages = []string{"before", "after"}
	}
	for _, message := range messages {
		if migrate && message == "after" {
			socket, err := net.ListenPacket("udp4", "127.0.0.1:0")
			if err != nil {
				log.Fatal(err)
			}
			if err := transport.replace(socket); err != nil {
				log.Fatal(err)
			}
		}
		if _, err := connection.Write([]byte(message)); err != nil {
			log.Fatal(err)
		}
		buffer := make([]byte, 64)
		n, err := connection.Read(buffer)
		if err != nil || string(buffer[:n]) != message {
			log.Fatalf("echo = %q, %v; want %q", buffer[:n], err, message)
		}
	}
	fmt.Println("client verified both echoes")
}

// rebindPacketConn models a NAT mapping change while retaining DTLS state.
type rebindPacketConn struct {
	mu sync.Mutex
	net.PacketConn
	writeDeadline time.Time
}

func (r *rebindPacketConn) replace(next net.PacketConn) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if err := next.SetWriteDeadline(r.writeDeadline); err != nil {
		return err
	}
	previous := r.PacketConn
	r.PacketConn = next
	return previous.Close()
}

func (r *rebindPacketConn) ReadFrom(data []byte) (int, net.Addr, error) {
	for {
		r.mu.Lock()
		current := r.PacketConn
		r.mu.Unlock()
		n, addr, err := current.ReadFrom(data)
		r.mu.Lock()
		replaced := current != r.PacketConn
		r.mu.Unlock()
		if replaced {
			continue
		}
		return n, addr, err
	}
}

func (r *rebindPacketConn) WriteTo(data []byte, peer net.Addr) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.PacketConn.WriteTo(data, peer)
}

func (r *rebindPacketConn) SetWriteDeadline(deadline time.Time) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.writeDeadline = deadline
	return r.PacketConn.SetWriteDeadline(deadline)
}

func (r *rebindPacketConn) LocalAddr() net.Addr {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.PacketConn.LocalAddr()
}

func (r *rebindPacketConn) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.PacketConn.Close()
}
