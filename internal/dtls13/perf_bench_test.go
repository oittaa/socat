package dtls13

import (
	"context"
	"crypto/tls"
	"io"
	"net"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// Steady-state microbenchmarks for DTLS 1.3 record and Conn hot paths.
//
// Handshake is excluded via b.ResetTimer. Default production Config is used
// (MTU 1200, default PQ groups and cipher preference). Application payload is
// 1024 bytes, matching the framed datagram size of the loopback goodput bench.
//
// Operation contents:
//
//   - BenchmarkEncodeRecord: one application record, send direction only.
//   - BenchmarkDecodeRecord: one application record, receive direction only.
//     The replay window is reset so this measures decryption, not uniqueness.
//   - BenchmarkDecodeRecordAuthFailure: one corrupted record, receive only.
//   - BenchmarkConnOneWay: one Write of 1024 bytes on an established
//     connection; a concurrent reader drains. One direction.
//   - BenchmarkConnPingPong: one Write plus one Read of 1024 bytes. Two
//     directions, one record each.
//
// Reproduction:
//
//	go test ./internal/dtls13 -bench BenchmarkEncodeRecord -benchmem -count=8
//	go test ./internal/dtls13 -bench BenchmarkDecodeRecord$ -benchmem -count=8
//	go test ./internal/dtls13 -bench BenchmarkConnOneWay -benchmem -count=8
//	go test ./internal/dtls13 -bench BenchmarkConnPingPong$ -benchmem -count=8
//
// Profiles (one benchmark per process so CPU/alloc samples do not mix):
//
//	go test ./internal/dtls13 -bench BenchmarkEncodeRecord -benchtime 3s -cpuprofile cpu-enc.pprof -memprofile mem-enc.pprof
//	go test ./internal/dtls13 -bench BenchmarkDecodeRecord$ -benchtime 3s -cpuprofile cpu-dec.pprof -memprofile mem-dec.pprof
//	go test ./internal/dtls13 -bench BenchmarkConnOneWay -benchtime 3s -cpuprofile cpu-oneway.pprof -memprofile mem-oneway.pprof
//	go test ./internal/dtls13 -bench BenchmarkConnPingPong$ -benchtime 3s -cpuprofile cpu-pong.pprof -memprofile mem-pong.pprof

const perfPayload = 1024

func perfUDP(tb testing.TB) *net.UDPConn {
	tb.Helper()
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		tb.Fatal(err)
	}
	tb.Cleanup(func() { _ = conn.Close() })
	return conn
}

func perfPair(tb testing.TB) (*Conn, *Conn, tls.ConnectionState) {
	tb.Helper()
	clientCfg, serverCfg := handshakeConfigs(tb)
	listener, err := Listen(perfUDP(tb), serverCfg)
	if err != nil {
		tb.Fatal(err)
	}
	tb.Cleanup(func() { _ = listener.Close() })
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	tb.Cleanup(cancel)
	client, err := Client(ctx, perfUDP(tb), listener.Addr(), clientCfg)
	if err != nil {
		tb.Fatal(err)
	}
	tb.Cleanup(func() { _ = client.Close() })
	peer, err := listener.AcceptContext(ctx)
	if err != nil {
		tb.Fatal(err)
	}
	server := peer.(*Conn)
	tb.Cleanup(func() { _ = server.Close() })
	state := client.ConnectionState()
	if !state.HandshakeComplete {
		tb.Fatal("handshake incomplete")
	}
	return client, server, state
}

func TestPerfHandshakeParameters(t *testing.T) {
	client, _, state := perfPair(t)
	t.Logf("go=%s os=%s arch=%s cpus=%d version=%s cipher=%s group=%s mtu_payload=%d payload=%d",
		runtime.Version(), runtime.GOOS, runtime.GOARCH, runtime.NumCPU(),
		tls.VersionName(state.Version), tls.CipherSuiteName(state.CipherSuite),
		state.CurveID, client.MaxDatagramSize(), perfPayload)
	if client.MaxDatagramSize() < perfPayload {
		t.Fatalf("payload %d exceeds MaxDatagramSize %d", perfPayload, client.MaxDatagramSize())
	}
}

func BenchmarkEncodeRecord(b *testing.B) {
	keys := testTrafficKeys(b)
	cid := make([]byte, 8)
	payload := make([]byte, perfPayload)
	b.SetBytes(int64(len(payload)))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		packet, err := keys.encodeRecord(recordNumber{3, uint64(i)}, cid, contentData, payload, 0)
		if err != nil || len(packet) == 0 {
			b.Fatal(err)
		}
	}
}

func BenchmarkDecodeRecord(b *testing.B) {
	keys := testTrafficKeys(b)
	cid := make([]byte, 8)
	payload := make([]byte, perfPayload)
	packet, err := keys.encodeRecord(recordNumber{3, 1}, cid, contentData, payload, 0)
	if err != nil {
		b.Fatal(err)
	}
	r, rest, err := parseRecord(packet, len(cid))
	if err != nil || len(rest) != 0 {
		b.Fatal(err)
	}
	b.SetBytes(int64(len(payload)))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		var window replayWindow
		_, typ, content, err := keys.decodeRecord(r, 3, cid, &window)
		if err != nil || typ != contentData || len(content) != len(payload) {
			b.Fatal(err)
		}
	}
}

func BenchmarkDecodeRecordAuthFailure(b *testing.B) {
	keys := testTrafficKeys(b)
	cid := make([]byte, 8)
	payload := make([]byte, perfPayload)
	packet, err := keys.encodeRecord(recordNumber{3, 1}, cid, contentData, payload, 0)
	if err != nil {
		b.Fatal(err)
	}
	packet = append([]byte(nil), packet...)
	packet[len(packet)-1] ^= 0xff
	r, rest, err := parseRecord(packet, len(cid))
	if err != nil || len(rest) != 0 {
		b.Fatal(err)
	}
	b.SetBytes(int64(len(payload)))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		var window replayWindow
		if _, _, _, err := keys.decodeRecord(r, 3, cid, &window); err == nil {
			b.Fatal("forged record accepted")
		}
	}
}

func BenchmarkConnOneWay(b *testing.B) {
	client, server, _ := perfPair(b)
	payload := make([]byte, perfPayload)
	var received atomic.Int64
	errc := make(chan error, 1)
	go func() {
		buf := make([]byte, len(payload))
		for {
			n, err := server.Read(buf)
			if n > 0 {
				received.Add(int64(n))
			}
			if err != nil {
				errc <- err
				return
			}
		}
	}()
	b.SetBytes(int64(len(payload)))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := client.Write(payload); err != nil {
			b.Fatal(err)
		}
	}
	b.StopTimer()
	_ = client.CloseWrite()
	select {
	case <-errc:
	case <-time.After(10 * time.Second):
		b.Fatal("reader timed out")
	}
	want := int64(b.N) * int64(len(payload))
	if got := received.Load(); got != want {
		b.ReportMetric(100*float64(want-got)/float64(want), "loss_pct")
	}
}

func BenchmarkConnPingPong(b *testing.B) {
	client, server, _ := perfPair(b)
	payload := make([]byte, perfPayload)
	got := make([]byte, len(payload))
	b.SetBytes(int64(len(payload)))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := client.Write(payload); err != nil {
			b.Fatal(err)
		}
		if _, err := io.ReadFull(server, got); err != nil {
			b.Fatal(err)
		}
	}
}

func TestConnWriteDoesNotRetainCallerBuffer(t *testing.T) {
	client, server, _ := perfPair(t)
	payload := []byte("owned-by-caller")
	if _, err := client.Write(payload); err != nil {
		t.Fatal(err)
	}
	payload[0] ^= 0xff
	buf := make([]byte, 32)
	n, err := server.Read(buf)
	if err != nil || string(buf[:n]) != "owned-by-caller" {
		t.Fatalf("caller buffer leaked into record: %q, %v", buf[:n], err)
	}
}

func TestConnWriteSnapshotBeforeReturn(t *testing.T) {
	client, server, _ := perfPair(t)
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		buf := make([]byte, 8)
		n, err := server.Read(buf)
		if err != nil || string(buf[:n]) != "before" {
			t.Errorf("write snapshot: %q, %v", buf[:n], err)
		}
	}()
	payload := []byte("before")
	if _, err := client.Write(payload); err != nil {
		t.Fatal(err)
	}
	copy(payload, "after!")
	wg.Wait()
}
