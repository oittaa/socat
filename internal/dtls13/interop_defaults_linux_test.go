//go:build linux && dtlsinterop

package dtls13

import (
	"bytes"
	"context"
	"crypto/mldsa"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
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

func defaultSettingsConfig(cert tls.Certificate, roots *x509.CertPool) *Config {
	return &Config{
		Certificates: []tls.Certificate{cert},
		RootCAs:      roots,
		ServerName:   "localhost",
		ClientCAs:    roots,
		ClientAuth:   tls.RequireAndVerifyClientCert,
	}
}

func defaultSettingsCertificate(t *testing.T, pq bool) (tls.Certificate, *x509.CertPool, string, string) {
	t.Helper()
	if !pq {
		return oracleCertificate(t)
	}
	cert, roots := mldsaCertificate(t, mldsa.MLDSA65())
	return writeOracleCertificate(t, cert, roots)
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

func checkDefaultSettingsState(state tls.ConnectionState, pq bool) error {
	if state.Version != version13 || len(state.VerifiedChains) == 0 {
		return fmt.Errorf("version=%x chains=%d", state.Version, len(state.VerifiedChains))
	}
	if !pq {
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
	for _, pq := range []bool{false, true} {
		name := "ecdsa-p256"
		if pq {
			name = "mldsa65"
		}
		t.Run(name+"/client", func(t *testing.T) {
			testDefaultOpenSSLServer(t, tools, pq)
		})
		t.Run(name+"/server", func(t *testing.T) {
			testDefaultOpenSSLClient(t, tools, pq)
		})
	}
}

func testDefaultOpenSSLServer(t *testing.T, tools oracleTools, pq bool) {
	t.Helper()
	cert, roots, certFile, keyFile := defaultSettingsCertificate(t, pq)
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
		"-CAfile", certFile, "-cert", certFile, "-key", keyFile)
	stdin, err := command.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	command.Stdout = stdin
	runOracle(t, command)
	client, err := Client(ctx, udpForOracle(t), address, defaultSettingsConfig(cert, roots))
	if err != nil {
		reportDefaultSettings(t, err, tls.ConnectionState{}, true)
		return
	}
	defer func() { _ = client.Close() }()
	if err := client.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
		t.Fatal(err)
	}
	state := client.ConnectionState()
	if err := checkDefaultSettingsState(state, pq); err != nil {
		reportDefaultSettings(t, err, state, true)
		return
	}
	reportDefaultSettings(t, echoDefaultSettings(client, []byte("default-openssl-server-echo\n")), state, true)
}

func testDefaultOpenSSLClient(t *testing.T, tools oracleTools, pq bool) {
	t.Helper()
	cert, roots, certFile, keyFile := defaultSettingsCertificate(t, pq)
	ctx, cancel := context.WithTimeout(context.Background(), defaultSettingsTimeout(true))
	defer cancel()
	conn := udpForOracle(t)
	listener, err := Listen(conn, defaultSettingsConfig(cert, roots))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = listener.Close() }()
	marker := []byte("default-openssl-client-echo\n")
	command := exec.CommandContext(ctx, tools.OpenSSL.OpenSSL,
		"s_client", "-dtls1_3", "-quiet", "-ign_eof",
		"-connect", conn.LocalAddr().String(), "-verify_hostname", "localhost",
		"-verify_return_error", "-CAfile", certFile, "-cert", certFile, "-key", keyFile)
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
	if err := checkDefaultSettingsState(state, pq); err != nil {
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
	// Pion has no ML-DSA signature schemes.
	for _, pq := range []bool{false, true} {
		name := "ecdsa-p256"
		if pq {
			name = "mldsa65"
		}
		t.Run(name+"/client", func(t *testing.T) {
			testDefaultPionServer(t, tools, pq, false)
		})
		t.Run(name+"/server", func(t *testing.T) {
			testDefaultPionClient(t, tools, pq, false)
		})
	}
}

func testDefaultPionServer(t *testing.T, tools oracleTools, pq, wantOK bool) {
	t.Helper()
	cert, roots, certFile, keyFile := defaultSettingsCertificate(t, pq)
	ctx, cancel := context.WithTimeout(context.Background(), defaultSettingsTimeout(wantOK))
	defer cancel()
	reservation := udpForOracle(t)
	address := reservation.LocalAddr().(*net.UDPAddr)
	if err := reservation.Close(); err != nil {
		t.Fatal(err)
	}
	command := exec.CommandContext(ctx, tools.Pion.Server, "-listen", address.String(), "-cert", certFile, "-key", keyFile)
	output, _ := runOracle(t, command)
	client, err := Client(ctx, udpForOracle(t), address, defaultSettingsConfig(cert, roots))
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
	if err := checkDefaultSettingsState(state, pq); err != nil {
		reportDefaultSettings(t, err, state, wantOK)
		return
	}
	reportDefaultSettings(t, echoDefaultSettings(client, []byte("default-pion-server-echo\n")), state, wantOK)
}

func testDefaultPionClient(t *testing.T, tools oracleTools, pq, wantOK bool) {
	t.Helper()
	cert, roots, certFile, keyFile := defaultSettingsCertificate(t, pq)
	ctx, cancel := context.WithTimeout(context.Background(), defaultSettingsTimeout(wantOK))
	defer cancel()
	conn := udpForOracle(t)
	listener, err := Listen(conn, defaultSettingsConfig(cert, roots))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = listener.Close() }()
	command := exec.CommandContext(ctx, tools.Pion.Server, "-connect", conn.LocalAddr().String(), "-cert", certFile, "-key", keyFile)
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
	if err := checkDefaultSettingsState(state, pq); err != nil {
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
	for _, pq := range []bool{false, true} {
		name := "ecdsa-p256"
		if pq {
			name = "mldsa65"
		}
		t.Run(name+"/client", func(t *testing.T) {
			testDefaultWolfSSLServer(t, tools, pq, false)
		})
		t.Run(name+"/server", func(t *testing.T) {
			// ECDSA: wolfSSL's client offers X25519MLKEM768 and completes at MTU 1200.
			// ML-DSA-65: the example client cannot load the certificate.
			testDefaultWolfSSLClient(t, tools, pq, !pq)
		})
	}
}

func testDefaultWolfSSLServer(t *testing.T, tools oracleTools, pq, wantOK bool) {
	t.Helper()
	cert, roots, certFile, keyFile := defaultSettingsCertificate(t, pq)
	ctx, cancel := context.WithTimeout(context.Background(), defaultSettingsTimeout(wantOK))
	defer cancel()
	reservation := udpForOracle(t)
	address := reservation.LocalAddr().(*net.UDPAddr)
	if err := reservation.Close(); err != nil {
		t.Fatal(err)
	}
	command := exec.CommandContext(ctx, tools.WolfSSL.Server,
		"-u", "-v", "4", "-Y", "-e", "-p", strconv.Itoa(address.Port),
		"-c", certFile, "-k", keyFile, "-A", certFile)
	command.Dir = filepath.Dir(tools.WolfSSL.Certificates)
	output, _ := runOracle(t, command)
	client, err := Client(ctx, udpForOracle(t), address, defaultSettingsConfig(cert, roots))
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
	if err := checkDefaultSettingsState(state, pq); err != nil {
		reportDefaultSettings(t, err, state, wantOK)
		return
	}
	reportDefaultSettings(t, echoDefaultSettings(client, []byte("default-wolfssl-server-echo\n")), state, wantOK)
}

func testDefaultWolfSSLClient(t *testing.T, tools oracleTools, pq, wantOK bool) {
	t.Helper()
	cert, roots, certFile, keyFile := defaultSettingsCertificate(t, pq)
	ctx, cancel := context.WithTimeout(context.Background(), defaultSettingsTimeout(wantOK))
	defer cancel()
	conn := udpForOracle(t)
	listener, err := Listen(conn, defaultSettingsConfig(cert, roots))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = listener.Close() }()
	port := listener.Addr().(*net.UDPAddr).Port
	command := exec.CommandContext(ctx, tools.WolfSSL.Client,
		"-u", "-v", "4", "-Y", "-h", "localhost", "-m", "-w", "-p", strconv.Itoa(port),
		"-c", certFile, "-k", keyFile, "-A", certFile)
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
	if err := checkDefaultSettingsState(state, pq); err != nil {
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
