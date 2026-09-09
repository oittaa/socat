//go:build linux

// Built explicitly by scripts/dtls13-pmtu-lab.py; uses only the public DTLS API.
package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"log"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"time"

	"github.com/oittaa/socat/internal/dtls13"
)

func emit(event string, fields map[string]any) {
	fields["event"], fields["time"] = event, time.Now().UnixNano()
	if err := json.NewEncoder(os.Stdout).Encode(fields); err != nil {
		log.Fatal(err)
	}
}

func credentials(dir string) error {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	cert := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "pmtu.lab"},
		DNSNames: []string{"pmtu.lab"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}}
	der, err := x509.CreateCertificate(rand.Reader, cert, cert, &key.PublicKey, key)
	if err != nil {
		return err
	}
	private, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(dir, "cert.pem"), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0600); err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, "key.pem"), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: private}), 0600)
}

func receipt(data []byte) []byte {
	sum := sha256.Sum256(data)
	return append(bytes.Clone(data[:8]), sum[:]...)
}

func serve(address string, config *dtls13.Config) error {
	pc, err := net.ListenPacket("udp", address)
	if err != nil {
		return err
	}
	l, err := dtls13.Listen(pc, config)
	if err != nil {
		_ = pc.Close()
		return err
	}
	defer l.Close()
	emit("listening", map[string]any{"address": pc.LocalAddr().String()})
	accepted, err := l.Accept()
	if err != nil {
		return err
	}
	c := accepted.(*dtls13.Conn)
	defer c.Close()
	if len(c.ConnectionState().VerifiedChains) == 0 {
		return errors.New("client certificate was not verified")
	}
	// Accept once: reconnecting cannot disguise loss of the original association.
	buf := make([]byte, 65535)
	for {
		n, err := c.Read(buf)
		if err != nil {
			return err
		}
		if n < 8 {
			return errors.New("short application message")
		}
		if _, err := c.Write(receipt(buf[:n])); err != nil {
			return err
		}
	}
}

func exchange(c *dtls13.Conn, sequence uint64, size int) (bool, error) {
	data := bytes.Repeat([]byte{0xa5}, size)
	binary.BigEndian.PutUint64(data, sequence)
	if err := c.SetDeadline(time.Now().Add(500 * time.Millisecond)); err != nil {
		return false, err
	}
	if _, err := c.Write(data); err != nil {
		if dtls13.IsDatagramTooLarge(err) {
			return false, nil
		}
		return false, err
	}
	want := receipt(data)
	buf := make([]byte, 64)
	for {
		n, err := c.Read(buf)
		if err != nil {
			if errors.Is(err, os.ErrDeadlineExceeded) {
				return false, nil
			}
			return false, err
		}
		if n < 8 || binary.BigEndian.Uint64(buf[:n]) != sequence {
			continue
		}
		if !bytes.Equal(buf[:n], want) {
			return false, errors.New("peer receipt does not match application payload")
		}
		return true, nil
	}
}

func client(address string, config *dtls13.Config) error {
	peer, err := net.ResolveUDPAddr("udp", address)
	if err != nil {
		return err
	}
	network := "udp4"
	if peer.IP.To4() == nil {
		network = "udp6"
	}
	pc, err := net.ListenPacket(network, ":0")
	if err != nil {
		return err
	}
	config.UnfragmentedProbes = true
	c, err := dtls13.Client(context.Background(), pc, peer, config)
	if err != nil {
		return err
	}
	defer c.Close()
	state := c.ConnectionState()
	if len(state.VerifiedChains) == 0 {
		return errors.New("server certificate was not verified")
	}
	emit("ready", map[string]any{"local": c.LocalAddr().String(), "peer": c.RemoteAddr().String(),
		"cipher": tls.CipherSuiteName(state.CipherSuite), "group": state.CurveID.String(), "max_datagram": c.MaxDatagramSize()})
	commands := make(chan string)
	go func() {
		scanner := bufio.NewScanner(os.Stdin)
		for scanner.Scan() {
			commands <- scanner.Text()
		}
		close(commands)
	}()
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	var sequence uint64
	for {
		sample := false
		select {
		case <-ticker.C:
		case command, ok := <-commands:
			if !ok || command == "stop" {
				return nil
			}
			if command != "sample" {
				return fmt.Errorf("unknown command %q", command)
			}
			sample = true
		}
		size := 64
		if sample {
			size = c.MaxDatagramSize()
		}
		sequence++
		ok, err := exchange(c, sequence, size)
		if err != nil {
			return err
		}
		emit("traffic", map[string]any{"sequence": sequence, "size": size, "ok": ok,
			"sample": sample, "max_datagram": c.MaxDatagramSize()})
	}
}

func run() error {
	dir := flag.String("credentials", "", "lab credential directory")
	generate := flag.Bool("generate", false, "generate a one-day lab certificate")
	listen := flag.String("listen", "", "server UDP address")
	connect := flag.String("connect", "", "client destination")
	flag.Parse()
	if *generate {
		return credentials(*dir)
	}
	cert, err := tls.LoadX509KeyPair(filepath.Join(*dir, "cert.pem"), filepath.Join(*dir, "key.pem"))
	if err != nil {
		return err
	}
	der, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return err
	}
	roots := x509.NewCertPool()
	roots.AddCert(der)
	config := &dtls13.Config{Certificates: []tls.Certificate{cert}, RootCAs: roots, ClientCAs: roots,
		ClientAuth: tls.RequireAndVerifyClientCert, ServerName: "pmtu.lab", MTU: 1440}
	if *listen != "" {
		return serve(*listen, config)
	}
	return client(*connect, config)
}

func main() {
	if err := run(); err != nil {
		log.Fatal(err)
	}
}
