//go:build linux && dtlsinterop

package dtls13

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/mldsa"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

// Default-settings interop: empty CipherSuites/CurvePreferences (library
// defaults), MTU 1200, CID length 8, migration on. Peers get a DTLS 1.3
// version flag and certificates only — no pinned groups, ciphers, --pqc,
// --force-curve, -l, -group, -cipher, or -migrate=false.
//
// Results fill the default-settings table in docs/dtls13.md.

type defaultAuth int

const (
	defaultECDSA defaultAuth = iota
	defaultMLDSA65
	defaultBoth // ML-DSA-65 leaf first, ECDSA P-256 leaf second; two CAs
)

func (a defaultAuth) String() string {
	switch a {
	case defaultMLDSA65:
		return "mldsa65"
	case defaultBoth:
		return "mldsa65+ecdsa-p256"
	default:
		return "ecdsa-p256"
	}
}

type defaultCreds struct {
	config                *Config
	certFile, keyFile     string
	serverCert, serverKey string
	dcertFile, dkeyFile   string
	caFile, caPath        string
}

func (c defaultCreds) opensslServerCert() (cert, key string) {
	if c.serverCert != "" {
		return c.serverCert, c.serverKey
	}
	return c.certFile, c.keyFile
}

func opensslTrustArgs(creds defaultCreds) []string {
	return []string{"-CApath", creds.caPath, "-CAfile", creds.caFile}
}

func opensslServerArgs(creds defaultCreds, accept string) []string {
	cert, key := creds.opensslServerCert()
	args := []string{
		"s_server", "-dtls1_3", "-quiet", "-ign_eof", "-naccept", "1",
		"-accept", accept, "-Verify", "1", "-verify_return_error",
		"-cert", cert, "-key", key,
	}
	args = append(args, opensslTrustArgs(creds)...)
	if creds.dcertFile != "" {
		args = append(args, "-dcert", creds.dcertFile, "-dkey", creds.dkeyFile)
	}
	return args
}

func opensslClientArgs(creds defaultCreds, connect string) []string {
	args := []string{
		"s_client", "-dtls1_3", "-quiet", "-ign_eof",
		"-connect", connect, "-verify_hostname", "localhost", "-verify_return_error",
		"-cert", creds.certFile, "-key", creds.keyFile,
	}
	return append(args, opensslTrustArgs(creds)...)
}

func defaultSettingsConfig(certs []tls.Certificate, roots *x509.CertPool) *Config {
	return &Config{
		Certificates: certs,
		RootCAs:      roots,
		ServerName:   "localhost",
		ClientCAs:    roots,
		ClientAuth:   tls.RequireAndVerifyClientCert,
	}
}

func ecdsaCertificate(t *testing.T) tls.Certificate {
	t.Helper()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ca := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "ECDSA CA"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	caDER, err := x509.CreateCertificate(rand.Reader, ca, ca, caKey.Public(), caKey)
	if err != nil {
		t.Fatal(err)
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	leaf := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "localhost"}, DNSNames: []string{"localhost"}, NotBefore: ca.NotBefore, NotAfter: ca.NotAfter, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}}
	der, err := x509.CreateCertificate(rand.Reader, leaf, ca, key.Public(), caKey)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der, caDER}, PrivateKey: key}
}

func certificateRoot(t *testing.T, cert tls.Certificate) *x509.Certificate {
	t.Helper()
	ca, err := x509.ParseCertificate(cert.Certificate[len(cert.Certificate)-1])
	if err != nil {
		t.Fatal(err)
	}
	return ca
}

func writeCAPEM(t *testing.T, cas ...*x509.Certificate) string {
	t.Helper()
	var pems []byte
	for _, ca := range cas {
		pems = append(pems, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca.Raw})...)
	}
	path := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(path, pems, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func writeCAPath(t *testing.T, openssl string, cas ...*x509.Certificate) string {
	t.Helper()
	if openssl == "" {
		t.Fatal("openssl binary required for CApath")
	}
	dir := t.TempDir()
	for i, ca := range cas {
		path := filepath.Join(dir, fmt.Sprintf("ca-%d.pem", i))
		if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca.Raw}), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	out, err := exec.Command(openssl, "rehash", dir).CombinedOutput()
	if err != nil {
		t.Fatalf("openssl rehash: %v\n%s", err, out)
	}
	return dir
}

func opensslTrust(t *testing.T, openssl string, cas ...*x509.Certificate) (caFile, caPath string) {
	t.Helper()
	return writeCAPEM(t, cas...), writeCAPath(t, openssl, cas...)
}

func defaultSettingsCertificate(t *testing.T, pq bool) (tls.Certificate, *x509.CertPool, string, string) {
	t.Helper()
	if !pq {
		return oracleCertificate(t)
	}
	cert, roots := mldsaCertificate(t, mldsa.MLDSA65())
	return writeOracleCertificate(t, cert, roots)
}

// defaultSettingsCreds builds our Config and the peer's cert files.
// defaultBoth is two CAs: ML-DSA CA signs the ML-DSA-65 leaf, ECDSA CA
// signs the ECDSA P-256 leaf. Verifiers trust both. OpenSSL loads them
// with -CApath (hashed) and -CAfile (PEM). s_server also gets both leaves
// (-cert ML-DSA-65, -dcert ECDSA). s_client presents ECDSA. Pion and
// wolfSSL cannot load ML-DSA, so they get the ECDSA leaf and ECDSA CA.
func defaultSettingsCreds(t *testing.T, auth defaultAuth, peer, openssl string) defaultCreds {
	t.Helper()
	switch auth {
	case defaultMLDSA65:
		cert, roots, certFile, keyFile := defaultSettingsCertificate(t, true)
		creds := defaultCreds{
			config:   defaultSettingsConfig([]tls.Certificate{cert}, roots),
			certFile: certFile,
			keyFile:  keyFile,
			caFile:   certFile,
		}
		if peer == "openssl" {
			creds.caFile, creds.caPath = opensslTrust(t, openssl, certificateRoot(t, cert))
		}
		return creds
	case defaultBoth:
		ec := ecdsaCertificate(t)
		pq, _ := mldsaCertificate(t, mldsa.MLDSA65())
		ecCA := certificateRoot(t, ec)
		pqCA := certificateRoot(t, pq)
		roots := x509.NewCertPool()
		roots.AddCert(ecCA)
		roots.AddCert(pqCA)
		_, _, ecFile, ecKey := writeOracleCertificate(t, ec, roots)
		_, _, pqFile, pqKey := writeOracleCertificate(t, pq, roots)
		creds := defaultCreds{
			config:   defaultSettingsConfig([]tls.Certificate{pq, ec}, roots),
			certFile: ecFile, keyFile: ecKey, caFile: writeCAPEM(t, ecCA),
		}
		if peer == "openssl" {
			creds.serverCert, creds.serverKey = pqFile, pqKey
			creds.dcertFile, creds.dkeyFile = ecFile, ecKey
			creds.caFile, creds.caPath = opensslTrust(t, openssl, pqCA, ecCA)
		}
		return creds
	default:
		cert, roots, certFile, keyFile := defaultSettingsCertificate(t, false)
		creds := defaultCreds{
			config:   defaultSettingsConfig([]tls.Certificate{cert}, roots),
			certFile: certFile, keyFile: keyFile, caFile: certFile,
		}
		if peer == "openssl" {
			creds.caFile, creds.caPath = opensslTrust(t, openssl, certificateRoot(t, cert))
		}
		return creds
	}
}

func logDefaultSettings(t *testing.T, conn *Conn) {
	t.Helper()
	state := conn.ConnectionState()
	if state.Version != version13 || len(state.VerifiedChains) == 0 {
		t.Fatalf("authentication: version=%x verified chains=%d", state.Version, len(state.VerifiedChains))
	}
	cert := state.PeerCertificates[0]
	keyType := cert.PublicKeyAlgorithm.String()
	switch key := cert.PublicKey.(type) {
	case *ecdsa.PublicKey:
		keyType += " " + key.Curve.Params().Name
	case *mldsa.PublicKey:
		keyType = key.Parameters().String()
	}
	t.Logf("negotiated suite=%s group=%s peer certificate=%s", tls.CipherSuiteName(state.CipherSuite), state.CurveID, keyType)
}

func TestDefaultSettingsOpenSSL(t *testing.T) {
	tools := loadOracleTools(t)
	if tools.OpenSSL.OpenSSL == "" {
		t.Fatal("OpenSSL binary is not listed in SOCAT_DTLS13_TOOLS")
	}
	for _, auth := range []defaultAuth{defaultECDSA, defaultMLDSA65, defaultBoth} {
		t.Run(auth.String()+"/client", func(t *testing.T) {
			testDefaultOpenSSLServer(t, tools, auth)
		})
		t.Run(auth.String()+"/server", func(t *testing.T) {
			testDefaultOpenSSLClient(t, tools, auth)
		})
	}
}

func testDefaultOpenSSLServer(t *testing.T, tools oracleTools, auth defaultAuth) {
	t.Helper()
	creds := defaultSettingsCreds(t, auth, "openssl", tools.OpenSSL.OpenSSL)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	reservation := udpForOracle(t)
	address := reservation.LocalAddr().(*net.UDPAddr)
	if err := reservation.Close(); err != nil {
		t.Fatal(err)
	}
	command := exec.CommandContext(ctx, tools.OpenSSL.OpenSSL, opensslServerArgs(creds, address.String())...)
	stdin, err := command.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	command.Stdout = stdin
	runOracle(t, command)
	client, err := Client(ctx, udpForOracle(t), address, creds.config)
	if err != nil {
		t.Fatalf("handshake: %v", err)
	}
	defer func() { _ = client.Close() }()
	if err := client.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
		t.Fatal(err)
	}
	logDefaultSettings(t, client)
	if err := echoWriteRead(client, []byte("default-openssl-server-echo\n")); err != nil {
		t.Fatalf("echo: %v", err)
	}
}

func testDefaultOpenSSLClient(t *testing.T, tools oracleTools, auth defaultAuth) {
	t.Helper()
	creds := defaultSettingsCreds(t, auth, "openssl", tools.OpenSSL.OpenSSL)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	conn := udpForOracle(t)
	listener, err := Listen(conn, creds.config)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = listener.Close() }()
	marker := []byte("default-openssl-client-echo\n")
	command := exec.CommandContext(ctx, tools.OpenSSL.OpenSSL, opensslClientArgs(creds, conn.LocalAddr().String())...)
	command.Stdin = strings.NewReader(string(marker))
	output, wait := runOracle(t, command)
	peer, err := listener.AcceptContext(ctx)
	if err != nil {
		t.Fatalf("handshake: %v", err)
	}
	defer func() { _ = peer.Close() }()
	if err := peer.SetDeadline(time.Now().Add(15 * time.Second)); err != nil {
		t.Fatal(err)
	}
	server := peer.(*Conn)
	logDefaultSettings(t, server)
	if err := echoReadWriteExpect(server, string(marker)); err != nil {
		t.Fatalf("exchange: %v", err)
	}
	if err := server.CloseWrite(); err != nil {
		t.Fatalf("exchange: %v", err)
	}
	if err := waitOracleContains(wait, output, marker); err != nil {
		t.Fatalf("peer completion: %v", err)
	}
}

func TestDefaultSettingsPion(t *testing.T) {
	tools := loadOracleTools(t)
	if tools.Pion.Server == "" {
		t.Fatal("Pion oracle is not listed in SOCAT_DTLS13_TOOLS")
	}
	// Public Client/Listen with CID/RRC on; Pion rejects CID-management messages.
	// Pion has no ML-DSA signature schemes; defaultBoth falls back to ECDSA.
	for _, auth := range []defaultAuth{defaultECDSA, defaultMLDSA65, defaultBoth} {
		t.Run(auth.String()+"/client", func(t *testing.T) {
			testDefaultPionServer(t, tools, auth)
		})
		t.Run(auth.String()+"/server", func(t *testing.T) {
			testDefaultPionClient(t, tools, auth)
		})
	}
}

func testDefaultPionServer(t *testing.T, tools oracleTools, auth defaultAuth) {
	t.Helper()
	creds := defaultSettingsCreds(t, auth, "pion", "")
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	reservation := udpForOracle(t)
	address := reservation.LocalAddr().(*net.UDPAddr)
	if err := reservation.Close(); err != nil {
		t.Fatal(err)
	}
	command := exec.CommandContext(ctx, tools.Pion.Server, "-listen", address.String(), "-cert", creds.certFile, "-key", creds.keyFile)
	runOracle(t, command)
	client, err := Client(ctx, udpForOracle(t), address, creds.config)
	if err != nil {
		t.Fatalf("handshake: %v", err)
	}
	defer func() { _ = client.Close() }()
	if err := client.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
		t.Fatal(err)
	}
	logDefaultSettings(t, client)
	if err := echoWriteRead(client, []byte("default-pion-server-echo\n")); err != nil {
		t.Fatalf("echo: %v", err)
	}
}

func testDefaultPionClient(t *testing.T, tools oracleTools, auth defaultAuth) {
	t.Helper()
	creds := defaultSettingsCreds(t, auth, "pion", "")
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	conn := udpForOracle(t)
	listener, err := Listen(conn, creds.config)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = listener.Close() }()
	command := exec.CommandContext(ctx, tools.Pion.Server, "-connect", conn.LocalAddr().String(), "-cert", creds.certFile, "-key", creds.keyFile)
	output, wait := runOracle(t, command)
	peer, err := listener.AcceptContext(ctx)
	if err != nil {
		t.Fatalf("handshake: %v", err)
	}
	defer func() { _ = peer.Close() }()
	if err := peer.SetDeadline(time.Now().Add(15 * time.Second)); err != nil {
		t.Fatal(err)
	}
	server := peer.(*Conn)
	logDefaultSettings(t, server)
	if err := echoReadWriteExpect(server, "before"); err != nil {
		t.Fatalf("exchange: %v", err)
	}
	if err := echoReadWriteExpect(server, "after"); err != nil {
		t.Fatalf("exchange: %v", err)
	}
	if err := waitOracleContains(wait, output, []byte("client verified both echoes")); err != nil {
		t.Fatalf("peer completion: %v", err)
	}
}

func TestDefaultSettingsWolfSSL(t *testing.T) {
	tools := loadOracleTools(t)
	if tools.WolfSSL.Server == "" || tools.WolfSSL.Client == "" {
		t.Skip("wolfSSL client/server binaries are not listed in SOCAT_DTLS13_TOOLS")
	}
	for _, auth := range []defaultAuth{defaultECDSA, defaultMLDSA65, defaultBoth} {
		t.Run(auth.String()+"/client", func(t *testing.T) {
			testDefaultWolfSSLServer(t, tools, auth)
		})
		t.Run(auth.String()+"/server", func(t *testing.T) {
			testDefaultWolfSSLClient(t, tools, auth)
		})
	}
}

func testDefaultWolfSSLServer(t *testing.T, tools oracleTools, auth defaultAuth) {
	t.Helper()
	creds := defaultSettingsCreds(t, auth, "wolfssl", "")
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	reservation := udpForOracle(t)
	address := reservation.LocalAddr().(*net.UDPAddr)
	if err := reservation.Close(); err != nil {
		t.Fatal(err)
	}
	command := exec.CommandContext(ctx, tools.WolfSSL.Server,
		"-u", "-v", "4", "-Y", "-e", "-p", strconv.Itoa(address.Port),
		"-c", creds.certFile, "-k", creds.keyFile, "-A", creds.caFile)
	command.Dir = filepath.Dir(tools.WolfSSL.Certificates)
	runOracle(t, command)
	client, err := Client(ctx, udpForOracle(t), address, creds.config)
	if err != nil {
		t.Fatalf("handshake: %v", err)
	}
	defer func() { _ = client.Close() }()
	if err := client.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
		t.Fatal(err)
	}
	logDefaultSettings(t, client)
	if err := echoWriteRead(client, []byte("default-wolfssl-server-echo\n")); err != nil {
		t.Fatalf("echo: %v", err)
	}
}

func testDefaultWolfSSLClient(t *testing.T, tools oracleTools, auth defaultAuth) {
	t.Helper()
	creds := defaultSettingsCreds(t, auth, "wolfssl", "")
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	conn := udpForOracle(t)
	listener, err := Listen(conn, creds.config)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = listener.Close() }()
	port := listener.Addr().(*net.UDPAddr).Port
	command := exec.CommandContext(ctx, tools.WolfSSL.Client,
		"-u", "-v", "4", "-Y", "-h", "localhost", "-m", "-w", "-p", strconv.Itoa(port),
		"-c", creds.certFile, "-k", creds.keyFile, "-A", creds.caFile)
	command.Dir = filepath.Dir(tools.WolfSSL.Certificates)
	output, wait := runOracle(t, command)
	peer, err := listener.AcceptContext(ctx)
	if err != nil {
		t.Fatalf("handshake: %v", err)
	}
	defer func() { _ = peer.Close() }()
	if err := peer.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
		t.Fatal(err)
	}
	server := peer.(*Conn)
	logDefaultSettings(t, server)
	got, err := echoReadWrite(server)
	if err != nil {
		t.Fatalf("exchange: %v", err)
	}
	if err := server.CloseWrite(); err != nil {
		t.Fatalf("exchange: %v", err)
	}
	if err := waitOracleContains(wait, output, got); err != nil {
		t.Fatalf("peer completion: %v", err)
	}
}
