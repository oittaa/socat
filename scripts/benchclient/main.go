// Command benchclient is a measure tool for scripts/bench.sh (TCP / TLS / QUIC).
// It is not a user CLI and is not installed.
package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"sort"
	"time"

	"github.com/quic-go/quic-go"
)

type result struct {
	OK       bool    `json:"ok"`
	Mode     string  `json:"mode"`
	Proto    string  `json:"proto"`
	N        int     `json:"n"`
	Size     int     `json:"size"`
	ElapsedS float64 `json:"elapsed_s"`
	MsgsS    float64 `json:"msgs_s,omitempty"`
	HsS      float64 `json:"hs_s,omitempty"`
	RTTUs    *stats  `json:"rtt_us,omitempty"`
	Version  string  `json:"version,omitempty"`
	Cipher   string  `json:"cipher,omitempty"`
	Group    string  `json:"group,omitempty"`
	ALPN     string  `json:"alpn,omitempty"`
	Error    string  `json:"error,omitempty"`
}

type stats struct {
	Median float64 `json:"median"`
	P99    float64 `json:"p99"`
	Min    float64 `json:"min"`
	Max    float64 `json:"max"`
}

func main() {
	var (
		mode       = flag.String("mode", "rr", "rr or hs")
		proto      = flag.String("proto", "tcp", "tcp, tls, or quic")
		addr       = flag.String("addr", "", "host:port")
		n          = flag.Int("n", 20000, "timed messages or handshakes")
		size       = flag.Int("size", 64, "payload bytes (rr) or 1 (hs)")
		warmup     = flag.Int("warmup", 1000, "untimed messages or handshakes")
		caPath     = flag.String("ca", "", "PEM CA file (tls/quic verify)")
		serverName = flag.String("servername", "localhost", "TLS/QUIC server name")
		alpn       = flag.String("alpn", "socat", "QUIC ALPN")
	)
	flag.Parse()
	if *addr == "" {
		fail(result{Mode: *mode, Proto: *proto, Error: "missing -addr"})
	}
	if *size < 1 {
		*size = 1
	}
	if *mode != "probe" && *n < 1 {
		fail(result{Mode: *mode, Proto: *proto, Error: "n must be >= 1"})
	}

	tlsCfg, err := clientTLS(*caPath, *serverName, *proto == "quic", *alpn)
	if err != nil {
		fail(result{Mode: *mode, Proto: *proto, Error: err.Error()})
	}

	var out result
	switch *mode {
	case "rr":
		out, err = runRR(*proto, *addr, tlsCfg, *n, *warmup, *size)
	case "hs":
		out, err = runHS(*proto, *addr, tlsCfg, *n, *warmup, *size)
	case "probe":
		out, err = runProbe(*proto, *addr, tlsCfg)
	default:
		fail(result{Mode: *mode, Proto: *proto, Error: "mode must be rr, hs, or probe"})
	}
	if err != nil {
		out.OK = false
		out.Error = err.Error()
		fail(out)
	}
	out.OK = true
	enc := json.NewEncoder(os.Stdout)
	if err := enc.Encode(out); err != nil {
		os.Exit(2)
	}
}

func fail(r result) {
	r.OK = false
	_ = json.NewEncoder(os.Stdout).Encode(r)
	os.Exit(1)
}

func clientTLS(caPath, serverName string, quic bool, alpn string) (*tls.Config, error) {
	cfg := &tls.Config{
		MinVersion: tls.VersionTLS12,
		ServerName: serverName,
	}
	if quic {
		cfg.MinVersion = tls.VersionTLS13
		cfg.NextProtos = []string{alpn}
	}
	if caPath == "" {
		return cfg, fmt.Errorf("missing -ca")
	}
	pem, err := os.ReadFile(caPath)
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		return nil, fmt.Errorf("ca: no certificates in %s", caPath)
	}
	cfg.RootCAs = pool
	return cfg, nil
}

type connIO interface {
	io.ReadWriter
	Close() error
}

func runRR(proto, addr string, tlsCfg *tls.Config, n, warmup, size int) (result, error) {
	c, closer, err := dial(proto, addr, tlsCfg)
	if err != nil {
		return result{Mode: "rr", Proto: proto}, err
	}
	defer closer()

	payload := make([]byte, size)
	for i := range payload {
		payload[i] = byte(i)
	}
	got := make([]byte, size)

	ping := func() (time.Duration, error) {
		t0 := time.Now()
		if _, err := c.Write(payload); err != nil {
			return 0, err
		}
		if _, err := io.ReadFull(c, got); err != nil {
			return 0, err
		}
		return time.Since(t0), nil
	}
	for i := 0; i < warmup; i++ {
		if _, err := ping(); err != nil {
			return result{Mode: "rr", Proto: proto, N: n, Size: size}, fmt.Errorf("warmup: %w", err)
		}
	}
	rtts := make([]float64, 0, n)
	t0 := time.Now()
	for i := 0; i < n; i++ {
		d, err := ping()
		if err != nil {
			return result{Mode: "rr", Proto: proto, N: n, Size: size}, fmt.Errorf("msg %d: %w", i, err)
		}
		rtts = append(rtts, float64(d.Nanoseconds())/1000.0)
	}
	elapsed := time.Since(t0)
	st := summarize(rtts)
	return result{
		Mode:     "rr",
		Proto:    proto,
		N:        n,
		Size:     size,
		ElapsedS: elapsed.Seconds(),
		MsgsS:    float64(n) / elapsed.Seconds(),
		RTTUs:    st,
	}, nil
}

func runHS(proto, addr string, tlsCfg *tls.Config, n, warmup, size int) (result, error) {
	payload := make([]byte, size)
	payload[0] = 0x61
	got := make([]byte, size)
	one := func() error {
		c, closer, err := dial(proto, addr, tlsCfg)
		if err != nil {
			return err
		}
		defer closer()
		if _, err := c.Write(payload); err != nil {
			return err
		}
		_, err = io.ReadFull(c, got)
		return err
	}
	for i := 0; i < warmup; i++ {
		if err := one(); err != nil {
			return result{Mode: "hs", Proto: proto, N: n, Size: size}, fmt.Errorf("warmup: %w", err)
		}
	}
	t0 := time.Now()
	for i := 0; i < n; i++ {
		if err := one(); err != nil {
			return result{Mode: "hs", Proto: proto, N: n, Size: size}, fmt.Errorf("hs %d: %w", i, err)
		}
	}
	elapsed := time.Since(t0)
	return result{
		Mode:     "hs",
		Proto:    proto,
		N:        n,
		Size:     size,
		ElapsedS: elapsed.Seconds(),
		HsS:      float64(n) / elapsed.Seconds(),
	}, nil
}

func dial(proto, addr string, tlsCfg *tls.Config) (connIO, func(), error) {
	switch proto {
	case "tcp":
		c, err := net.DialTimeout("tcp", addr, 5*time.Second)
		if err != nil {
			return nil, nil, err
		}
		return c, func() { _ = c.Close() }, nil
	case "tls":
		d := &net.Dialer{Timeout: 5 * time.Second}
		c, err := tls.DialWithDialer(d, "tcp", addr, tlsCfg)
		if err != nil {
			return nil, nil, err
		}
		return c, func() { _ = c.Close() }, nil
	case "quic":
		return dialQUIC(addr, tlsCfg)
	default:
		return nil, nil, fmt.Errorf("unknown proto %q", proto)
	}
}

func runProbe(proto, addr string, tlsCfg *tls.Config) (result, error) {
	out := result{Mode: "probe", Proto: proto}
	switch proto {
	case "tls":
		d := &net.Dialer{Timeout: 5 * time.Second}
		c, err := tls.DialWithDialer(d, "tcp", addr, tlsCfg)
		if err != nil {
			return out, err
		}
		fillTLS(&out, c.ConnectionState())
		_ = c.Close()
		return out, nil
	case "quic":
		return probeQUIC(addr, tlsCfg)
	default:
		return out, fmt.Errorf("probe proto must be tls or quic")
	}
}

func probeQUIC(addr string, tlsCfg *tls.Config) (result, error) {
	out := result{Mode: "probe", Proto: "quic"}
	raddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return out, err
	}
	pc, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		return out, err
	}
	tr := &quic.Transport{Conn: pc}
	defer func() {
		_ = tr.Close()
		_ = pc.Close()
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	qc, err := tr.Dial(ctx, raddr, tlsCfg.Clone(), &quic.Config{})
	if err != nil {
		return out, err
	}
	defer func() { _ = qc.CloseWithError(0, "") }()
	fillTLS(&out, qc.ConnectionState().TLS)
	if out.ALPN == "" {
		out.ALPN = "socat"
	}
	return out, nil
}

func fillTLS(out *result, cs tls.ConnectionState) {
	out.Version = tls.VersionName(cs.Version)
	out.Cipher = tls.CipherSuiteName(cs.CipherSuite)
	if cs.CurveID != 0 {
		out.Group = cs.CurveID.String()
	}
	out.ALPN = cs.NegotiatedProtocol
}

func dialQUIC(addr string, tlsCfg *tls.Config) (connIO, func(), error) {
	raddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return nil, nil, err
	}
	pc, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		return nil, nil, err
	}
	tr := &quic.Transport{Conn: pc}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	qc, err := tr.Dial(ctx, raddr, tlsCfg.Clone(), &quic.Config{})
	if err != nil {
		_ = tr.Close()
		_ = pc.Close()
		return nil, nil, err
	}
	st, err := qc.OpenStreamSync(ctx)
	if err != nil {
		_ = qc.CloseWithError(0, "")
		_ = tr.Close()
		_ = pc.Close()
		return nil, nil, err
	}
	closeFn := func() {
		_ = st.Close()
		_ = qc.CloseWithError(0, "")
		_ = tr.Close()
		_ = pc.Close()
	}
	return st, closeFn, nil
}

func summarize(v []float64) *stats {
	if len(v) == 0 {
		return &stats{}
	}
	s := append([]float64(nil), v...)
	sort.Float64s(s)
	return &stats{
		Median: percentile(s, 50),
		P99:    percentile(s, 99),
		Min:    s[0],
		Max:    s[len(s)-1],
	}
}

func percentile(sorted []float64, p float64) float64 {
	if len(sorted) == 0 {
		return 0
	}
	if p <= 0 {
		return sorted[0]
	}
	if p >= 100 {
		return sorted[len(sorted)-1]
	}
	idx := int(float64(len(sorted)-1) * p / 100.0)
	return sorted[idx]
}
