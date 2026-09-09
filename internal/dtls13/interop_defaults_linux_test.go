//go:build linux && dtlsinterop

package dtls13

import (
	"bytes"
	"context"
	"crypto/mldsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
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
	defaultBoth // ML-DSA-65 first, ECDSA P-256 second, on our Config only
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
	config            *Config
	certFile, keyFile string
	caFile            string
	expectPeerMLDSA   bool
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

func writeCertificatePEM(t *testing.T, der []byte) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
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
// For defaultBoth, our slice is ML-DSA-65 then ECDSA P-256. The peer process
// still loads ECDSA P-256 (Pion and wolfSSL cannot load ML-DSA). OpenSSL's
// CAfile is the ML-DSA CA so the handshake fails unless we selected the PQ cert.
func defaultSettingsCreds(t *testing.T, auth defaultAuth, peer string) defaultCreds {
	t.Helper()
	switch auth {
	case defaultMLDSA65:
		cert, roots, certFile, keyFile := defaultSettingsCertificate(t, true)
		return defaultCreds{config: defaultSettingsConfig([]tls.Certificate{cert}, roots), certFile: certFile, keyFile: keyFile, caFile: certFile, expectPeerMLDSA: true}
	case defaultBoth:
		ec, _, ecFile, ecKey := oracleCertificate(t)
		pq, _ := mldsaCertificate(t, mldsa.MLDSA65())
		ecLeaf, err := x509.ParseCertificate(ec.Certificate[0])
		if err != nil {
			t.Fatal(err)
		}
		pqCA, err := x509.ParseCertificate(pq.Certificate[len(pq.Certificate)-1])
		if err != nil {
			t.Fatal(err)
		}
		roots := x509.NewCertPool()
		roots.AddCert(ecLeaf)
		roots.AddCert(pqCA)
		caFile := ecFile
		if peer == "openssl" {
			caFile = writeCertificatePEM(t, pq.Certificate[len(pq.Certificate)-1])
		}
		return defaultCreds{
			config:   defaultSettingsConfig([]tls.Certificate{pq, ec}, roots),
			certFile: ecFile, keyFile: ecKey, caFile: caFile,
		}
	default:
		cert, roots, certFile, keyFile := defaultSettingsCertificate(t, false)
		return defaultCreds{config: defaultSettingsConfig([]tls.Certificate{cert}, roots), certFile: certFile, keyFile: keyFile, caFile: certFile}
	}
}

func defaultSettingsTimeout(wantOK bool) time.Duration {
	if wantOK {
		return 30 * time.Second
	}
	return 12 * time.Second
}

func reportDefaultSettings(t *testing.T, err error, state tls.ConnectionState, wantOK bool) {
	t.Helper()
	if state.CipherSuite != 0 || state.CurveID != 0 {
		t.Logf("negotiated suite=%s group=%s", tls.CipherSuiteName(state.CipherSuite), state.CurveID)
	}
	if err != nil {
		t.Logf("default-settings result: %v", err)
		if wantOK {
			t.Fatal(err)
		}
		return
	}
	if !wantOK {
		t.Errorf("succeeded (suite=%s group=%s); update docs/dtls13.md default-settings table", tls.CipherSuiteName(state.CipherSuite), state.CurveID)
	}
}

func checkDefaultSettingsState(state tls.ConnectionState, expectPeerMLDSA bool) error {
	if state.Version != version13 || len(state.VerifiedChains) == 0 {
		return fmt.Errorf("version=%x chains=%d", state.Version, len(state.VerifiedChains))
	}
	if !expectPeerMLDSA {
		return nil
	}
	key, ok := state.PeerCertificates[0].PublicKey.(*mldsa.PublicKey)
	if !ok || key.Parameters() != mldsa.MLDSA65() {
		return fmt.Errorf("peer certificate is not ML-DSA-65")
	}
	return nil
}

func echoDefaultSettings(conn *Conn, marker []byte) error {
	if _, err := conn.Write(marker); err != nil {
		return err
	}
	buffer := make([]byte, 1024)
	n, err := conn.Read(buffer)
	if err != nil {
		return err
	}
	if !bytes.Equal(buffer[:n], marker) {
		return fmt.Errorf("echo %q", buffer[:n])
	}
	return nil
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
	creds := defaultSettingsCreds(t, auth, "openssl")
	ctx, cancel := context.WithTimeout(context.Background(), defaultSettingsTimeout(true))
	defer cancel()
	reservation := udpForOracle(t)
	address := reservation.LocalAddr().(*net.UDPAddr)
	if err := reservation.Close(); err != nil {
		t.Fatal(err)
	}
	command := exec.CommandContext(ctx, tools.OpenSSL.OpenSSL,
		"s_server", "-dtls1_3", "-quiet", "-ign_eof", "-naccept", "1",
		"-accept", address.String(), "-Verify", "1", "-verify_return_error",
		"-CAfile", creds.caFile, "-cert", creds.certFile, "-key", creds.keyFile)
	stdin, err := command.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	command.Stdout = stdin
	runOracle(t, command)
	client, err := Client(ctx, udpForOracle(t), address, creds.config)
	if err != nil {
		reportDefaultSettings(t, err, tls.ConnectionState{}, true)
		return
	}
	defer func() { _ = client.Close() }()
	if err := client.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
		t.Fatal(err)
	}
	state := client.ConnectionState()
	if err := checkDefaultSettingsState(state, creds.expectPeerMLDSA); err != nil {
		reportDefaultSettings(t, err, state, true)
		return
	}
	reportDefaultSettings(t, echoDefaultSettings(client, []byte("default-openssl-server-echo\n")), state, true)
}

func testDefaultOpenSSLClient(t *testing.T, tools oracleTools, auth defaultAuth) {
	t.Helper()
	creds := defaultSettingsCreds(t, auth, "openssl")
	ctx, cancel := context.WithTimeout(context.Background(), defaultSettingsTimeout(true))
	defer cancel()
	conn := udpForOracle(t)
	listener, err := Listen(conn, creds.config)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = listener.Close() }()
	marker := []byte("default-openssl-client-echo\n")
	command := exec.CommandContext(ctx, tools.OpenSSL.OpenSSL,
		"s_client", "-dtls1_3", "-quiet", "-ign_eof",
		"-connect", conn.LocalAddr().String(), "-verify_hostname", "localhost",
		"-verify_return_error", "-CAfile", creds.caFile, "-cert", creds.certFile, "-key", creds.keyFile)
	command.Stdin = strings.NewReader(string(marker))
	output, wait := runOracle(t, command)
	peer, err := listener.AcceptContext(ctx)
	if err != nil {
		reportDefaultSettings(t, err, tls.ConnectionState{}, true)
		return
	}
	defer func() { _ = peer.Close() }()
	if err := peer.SetDeadline(time.Now().Add(15 * time.Second)); err != nil {
		t.Fatal(err)
	}
	server := peer.(*Conn)
	state := server.ConnectionState()
	if err := checkDefaultSettingsState(state, creds.expectPeerMLDSA); err != nil {
		reportDefaultSettings(t, err, state, true)
		return
	}
	buffer := make([]byte, 1024)
	n, err := server.Read(buffer)
	if err != nil || !bytes.Equal(buffer[:n], marker) {
		reportDefaultSettings(t, fmt.Errorf("OpenSSL data %q, %v", buffer[:n], err), state, true)
		return
	}
	if _, err := server.Write(marker); err != nil {
		reportDefaultSettings(t, err, state, true)
		return
	}
	if err := server.CloseWrite(); err != nil {
		reportDefaultSettings(t, err, state, true)
		return
	}
	if err := wait(); err != nil {
		reportDefaultSettings(t, err, state, true)
		return
	}
	if !bytes.Contains(output.Bytes(), marker) {
		reportDefaultSettings(t, fmt.Errorf("OpenSSL did not verify and decrypt our response"), state, true)
		return
	}
	reportDefaultSettings(t, nil, state, true)
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
			testDefaultPionServer(t, tools, auth, false)
		})
		t.Run(auth.String()+"/server", func(t *testing.T) {
			testDefaultPionClient(t, tools, auth, false)
		})
	}
}

func testDefaultPionServer(t *testing.T, tools oracleTools, auth defaultAuth, wantOK bool) {
	t.Helper()
	creds := defaultSettingsCreds(t, auth, "pion")
	ctx, cancel := context.WithTimeout(context.Background(), defaultSettingsTimeout(wantOK))
	defer cancel()
	reservation := udpForOracle(t)
	address := reservation.LocalAddr().(*net.UDPAddr)
	if err := reservation.Close(); err != nil {
		t.Fatal(err)
	}
	command := exec.CommandContext(ctx, tools.Pion.Server, "-listen", address.String(), "-cert", creds.certFile, "-key", creds.keyFile)
	output, _ := runOracle(t, command)
	client, err := Client(ctx, udpForOracle(t), address, creds.config)
	if err != nil {
		t.Logf("oracle output:\n%s", output.String())
		reportDefaultSettings(t, err, tls.ConnectionState{}, wantOK)
		return
	}
	defer func() { _ = client.Close() }()
	if err := client.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
		t.Fatal(err)
	}
	state := client.ConnectionState()
	if err := checkDefaultSettingsState(state, creds.expectPeerMLDSA); err != nil {
		reportDefaultSettings(t, err, state, wantOK)
		return
	}
	reportDefaultSettings(t, echoDefaultSettings(client, []byte("default-pion-server-echo\n")), state, wantOK)
}

func testDefaultPionClient(t *testing.T, tools oracleTools, auth defaultAuth, wantOK bool) {
	t.Helper()
	creds := defaultSettingsCreds(t, auth, "pion")
	ctx, cancel := context.WithTimeout(context.Background(), defaultSettingsTimeout(wantOK))
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
		t.Logf("oracle output:\n%s", output.String())
		reportDefaultSettings(t, err, tls.ConnectionState{}, wantOK)
		return
	}
	defer func() { _ = peer.Close() }()
	if err := peer.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
		t.Fatal(err)
	}
	server := peer.(*Conn)
	state := server.ConnectionState()
	if err := checkDefaultSettingsState(state, creds.expectPeerMLDSA); err != nil {
		t.Logf("oracle output:\n%s", output.String())
		reportDefaultSettings(t, err, state, wantOK)
		return
	}
	buffer := make([]byte, 1024)
	n, err := server.Read(buffer)
	if err != nil || n == 0 {
		t.Logf("oracle output:\n%s", output.String())
		reportDefaultSettings(t, fmt.Errorf("Pion data %q, %v", buffer[:n], err), state, wantOK)
		return
	}
	if _, err := server.Write(buffer[:n]); err != nil {
		reportDefaultSettings(t, err, state, wantOK)
		return
	}
	_ = wait()
	reportDefaultSettings(t, nil, state, wantOK)
}

func TestDefaultSettingsWolfSSL(t *testing.T) {
	tools := loadOracleTools(t)
	if tools.WolfSSL.Server == "" || tools.WolfSSL.Client == "" {
		t.Skip("wolfSSL client/server binaries are not listed in SOCAT_DTLS13_TOOLS")
	}
	for _, auth := range []defaultAuth{defaultECDSA, defaultMLDSA65, defaultBoth} {
		t.Run(auth.String()+"/client", func(t *testing.T) {
			testDefaultWolfSSLServer(t, tools, auth, false)
		})
		t.Run(auth.String()+"/server", func(t *testing.T) {
			// ECDSA and dual-cert fallback: wolfSSL's client offers X25519MLKEM768
			// and completes at MTU 1200. ML-DSA-65 only: the example cannot load the cert.
			testDefaultWolfSSLClient(t, tools, auth, auth != defaultMLDSA65)
		})
	}
}

func testDefaultWolfSSLServer(t *testing.T, tools oracleTools, auth defaultAuth, wantOK bool) {
	t.Helper()
	creds := defaultSettingsCreds(t, auth, "wolfssl")
	ctx, cancel := context.WithTimeout(context.Background(), defaultSettingsTimeout(wantOK))
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
	output, _ := runOracle(t, command)
	client, err := Client(ctx, udpForOracle(t), address, creds.config)
	if err != nil {
		t.Logf("oracle output:\n%s", output.String())
		reportDefaultSettings(t, err, tls.ConnectionState{}, wantOK)
		return
	}
	defer func() { _ = client.Close() }()
	if err := client.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
		t.Fatal(err)
	}
	state := client.ConnectionState()
	if err := checkDefaultSettingsState(state, creds.expectPeerMLDSA); err != nil {
		reportDefaultSettings(t, err, state, wantOK)
		return
	}
	reportDefaultSettings(t, echoDefaultSettings(client, []byte("default-wolfssl-server-echo\n")), state, wantOK)
}

func testDefaultWolfSSLClient(t *testing.T, tools oracleTools, auth defaultAuth, wantOK bool) {
	t.Helper()
	creds := defaultSettingsCreds(t, auth, "wolfssl")
	ctx, cancel := context.WithTimeout(context.Background(), defaultSettingsTimeout(wantOK))
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
		t.Logf("oracle output:\n%s", output.String())
		reportDefaultSettings(t, err, tls.ConnectionState{}, wantOK)
		return
	}
	defer func() { _ = peer.Close() }()
	if err := peer.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
		t.Fatal(err)
	}
	server := peer.(*Conn)
	state := server.ConnectionState()
	if err := checkDefaultSettingsState(state, creds.expectPeerMLDSA); err != nil {
		t.Logf("oracle output:\n%s", output.String())
		reportDefaultSettings(t, err, state, wantOK)
		return
	}
	buffer := make([]byte, 1024)
	n, err := server.Read(buffer)
	if err != nil || n == 0 {
		t.Logf("oracle output:\n%s", output.String())
		reportDefaultSettings(t, fmt.Errorf("wolfSSL data %q, %v", buffer[:n], err), state, wantOK)
		return
	}
	if _, err := server.Write(buffer[:n]); err != nil {
		reportDefaultSettings(t, err, state, wantOK)
		return
	}
	_ = wait()
	reportDefaultSettings(t, nil, state, wantOK)
}
