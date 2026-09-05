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
	"github.com/pion/dtls/v3/pkg/protocol"
)

func main() {
	address := flag.String("listen", "127.0.0.1:0", "UDP listen address")
	connect := flag.String("connect", "", "run a two-datagram client against this address")
	certFile := flag.String("cert", "", "certificate and trust anchor")
	keyFile := flag.String("key", "", "private key")
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
		runClient(*connect, cert, roots)
		return
	}
	addr, err := net.ResolveUDPAddr("udp4", *address)
	if err != nil {
		log.Fatal(err)
	}
	listener, err := dtls.ListenAddr("udp4", addr,
		dtls.WithCertificates(cert), dtls.WithClientCAs(roots),
		dtls.WithClientAuth(dtls.RequireAndVerifyClientCert),
		dtls.WithMinVersion(protocol.Version1_3), dtls.WithMaxVersion(protocol.Version1_3),
		dtls.WithConnectionID(func() []byte {
			id := make([]byte, 8)
			if _, err := rand.Read(id); err != nil {
				log.Fatal(err)
			}
			return id
		}, dtls.CIDPathMigrationRRC))
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
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
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

func runClient(address string, cert tls.Certificate, roots *x509.CertPool) {
	peer, err := net.ResolveUDPAddr("udp4", address)
	if err != nil {
		log.Fatal(err)
	}
	socket, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		log.Fatal(err)
	}
	transport := &rebindPacketConn{PacketConn: socket}
	connection, err := dtls.Client(transport, peer,
		dtls.WithCertificates(cert), dtls.WithRootCAs(roots), dtls.WithServerName("localhost"),
		dtls.WithMinVersion(protocol.Version1_3), dtls.WithMaxVersion(protocol.Version1_3),
		dtls.WithConnectionID(func() []byte {
			id := make([]byte, 8)
			if _, err := rand.Read(id); err != nil {
				log.Fatal(err)
			}
			return id
		}, dtls.CIDPathMigrationRRC))
	if err != nil {
		log.Fatal(err)
	}
	defer connection.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	if err := connection.HandshakeContext(ctx); err != nil {
		log.Fatal(err)
	}
	if err := connection.SetDeadline(time.Now().Add(15 * time.Second)); err != nil {
		log.Fatal(err)
	}
	for _, message := range []string{"before", "after"} {
		if message == "after" {
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
