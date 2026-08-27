package proxyopen

import (
	"bufio"
	"bytes"
	"testing"
)

func FuzzProxyStatusOK(f *testing.F) {
	for _, seed := range []string{
		"HTTP/1.0 200 OK\r\n", "HTTP/1.1   403 Forbidden\n", "HTTP/2 200\r\n", "",
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, status string) {
		if len(status) > maxHTTP1ProxyResponseBytes+1 {
			t.Skip()
		}
		_ = proxyStatusOK(status)
	})
}

func FuzzProxyResponseLine(f *testing.F) {
	for _, seed := range [][]byte{
		[]byte("HTTP/1.1 200 OK\r\n"), []byte("header without newline"), bytes.Repeat([]byte{'x'}, 4097),
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > maxHTTP1ProxyResponseBytes+2 {
			t.Skip()
		}
		for _, ignoreCR := range []bool{false, true} {
			total := 0
			_, _ = readProxyResponseLine(bufio.NewReaderSize(bytes.NewReader(data), maxHTTP1ProxyResponseBytes+1), &total, ignoreCR)
			if total > len(data) {
				t.Fatalf("ignorecr=%v parser consumed %d bytes from %d-byte input", ignoreCR, total, len(data))
			}
		}
	})
}

func FuzzSOCKS4Reply(f *testing.F) {
	for _, seed := range [][]byte{
		{0, 90, 0, 0, 0, 0, 0, 0},
		{0, 91, 0, 0, 0, 0, 0, 0},
		{0, 90},
		{},
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, reply []byte) {
		if len(reply) > 4096 {
			t.Skip()
		}
		_ = socks4ReadReply(bytes.NewReader(reply))
	})
}

func FuzzSOCKS5Reply(f *testing.F) {
	for _, seed := range [][]byte{
		{5, 0, 0, 1, 127, 0, 0, 1, 0, 80},
		{5, 0, 0, 3, 3, 'f', 'o', 'o', 0, 80},
		{5, 1, 0, 4},
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, reply []byte) {
		if len(reply) > 4096 {
			t.Skip()
		}
		_ = socks5ReadReply(bytes.NewReader(reply))
	})
}
