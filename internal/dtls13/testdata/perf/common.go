// Built explicitly for scripts/dtls13-perf.py, outside ordinary tests.
package main

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"os"
	"runtime"
	"runtime/pprof"
	"time"
)

func must(err error) {
	if err != nil {
		panic(err)
	}
}

func credentials(certFile, keyFile, caFile string) (tls.Certificate, *x509.CertPool) {
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	must(err)
	pem, err := os.ReadFile(caFile)
	must(err)
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(pem) {
		panic("empty trust store")
	}
	return cert, roots
}

func socket() *net.UDPConn {
	c, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	must(err)
	return c
}

func write(c net.Conn, data []byte) {
	n, err := c.Write(data)
	must(err)
	if n != len(data) {
		panic("short write")
	}
}

func read(c net.Conn, buf, want []byte) {
	n, err := c.Read(buf)
	must(err)
	if n != len(want) || !bytes.Equal(buf[:n], want) {
		panic("invalid application datagram")
	}
}

func main() {
	certFile := flag.String("cert", "", "server certificate")
	keyFile := flag.String("key", "", "server key")
	caFile := flag.String("ca", "", "trust anchor")
	n := flag.Int("n", 100000, "timed operations")
	warmup := flag.Int("warmup", 1000, "untimed round trips")
	mode := flag.String("mode", "rr", "rr or oneway")
	cpuProfile := flag.String("cpu-profile", "", "optional CPU profile (separate from timing runs)")
	memProfile := flag.String("mem-profile", "", "optional heap/allocation profile")
	flag.Parse()
	if *n <= 0 || *warmup < 0 {
		panic("invalid operation count")
	}
	cert, roots := credentials(*certFile, *keyFile, *caFile)
	client, server, cleanup := pair(cert, roots)
	defer cleanup()
	watchdog := time.AfterFunc(2*time.Minute, func() { panic("benchmark timed out") })
	defer watchdog.Stop()
	payload, reply := make([]byte, 1024), make([]byte, 1024)
	for i := range payload {
		payload[i] = byte(i)
	}
	// Drain handshake traffic and warm both application directions before timing.
	for range *warmup {
		write(client, payload)
		read(server, reply, payload)
		write(server, reply)
		read(client, reply, payload)
	}
	if *cpuProfile != "" {
		file, err := os.Create(*cpuProfile)
		must(err)
		must(pprof.StartCPUProfile(file))
		defer func() { pprof.StopCPUProfile(); must(file.Close()) }()
	}
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	row := map[string]any{"library": library, "mode": *mode, "n": *n, "frame_bytes": 1024, "mtu": 1200, "version": "DTLS 1.3", "cipher": "TLS_AES_128_GCM_SHA256", "group": "X25519", "cid": false, "go": runtime.Version()}
	if *mode == "rr" {
		done := make(chan struct{})
		go func() {
			buf := make([]byte, 1024)
			for range *n {
				read(server, buf, payload)
				write(server, buf)
			}
			close(done)
		}()
		start := time.Now()
		for range *n {
			write(client, payload)
			read(client, reply, payload)
		}
		elapsed := time.Since(start).Seconds()
		<-done
		row["elapsed_s"], row["rtt_us"], row["request_mib_s"] = elapsed, elapsed*1e6/float64(*n), float64(*n)*1024/(1<<20)/elapsed
	} else if *mode == "oneway" {
		type delivery struct {
			count, duplicate, reorder int
			last                      time.Time
		}
		results, ready := make(chan delivery, 1), make(chan struct{})
		go func() {
			buf, seen := make([]byte, 1024), make([]bool, *n)
			d, highest := delivery{}, -1
			close(ready)
			for {
				got, err := server.Read(buf)
				if err != nil {
					if timeout, ok := err.(net.Error); !ok || !timeout.Timeout() {
						panic(err)
					}
					break
				}
				seq := binary.BigEndian.Uint64(buf)
				if got != len(buf) || seq >= uint64(*n) || !bytes.Equal(buf[8:], payload[8:]) {
					panic("invalid datagram")
				}
				if seen[seq] {
					d.duplicate++
					continue
				}
				seen[seq] = true
				d.count++
				d.last = time.Now()
				if int(seq) < highest {
					d.reorder++
				}
				if int(seq) > highest {
					highest = int(seq)
				}
			}
			results <- d
		}()
		<-ready
		start := time.Now()
		for i := range *n {
			binary.BigEndian.PutUint64(payload, uint64(i))
			write(client, payload)
		}
		sendElapsed := time.Since(start).Seconds()
		must(server.SetReadDeadline(time.Now().Add(250 * time.Millisecond)))
		d := <-results
		if d.count == 0 {
			panic("no application data received")
		}
		elapsed := max(sendElapsed, d.last.Sub(start).Seconds())
		row["send_mib_s"], row["receive_mib_s"] = float64(*n)*1024/(1<<20)/sendElapsed, float64(d.count)*1024/(1<<20)/elapsed
		row["loss_pct"], row["duplicate"], row["reorder"] = 100*float64(*n-d.count)/float64(*n), d.duplicate, d.reorder
		row["elapsed_s"], row["received"] = elapsed, d.count
	} else {
		panic("unknown mode")
	}
	runtime.ReadMemStats(&after)
	row["allocs_per_op"] = float64(after.Mallocs-before.Mallocs) / float64(*n)
	row["bytes_per_op"] = float64(after.TotalAlloc-before.TotalAlloc) / float64(*n)
	if *memProfile != "" {
		file, err := os.Create(*memProfile)
		must(err)
		runtime.GC()
		must(pprof.WriteHeapProfile(file))
		must(file.Close())
	}
	encoded, err := json.Marshal(row)
	must(err)
	fmt.Println(string(encoded))
}
