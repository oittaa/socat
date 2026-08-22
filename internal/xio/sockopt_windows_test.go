//go:build windows

package xio

import (
	"errors"
	"net"
	"testing"

	"github.com/oittaa/socat/internal/parse"
	"golang.org/x/sys/windows"
)

func TestWindowsTimeoutMillis(t *testing.T) {
	tests := []struct {
		value   string
		want    uint32
		wantErr bool
	}{
		{value: "0", want: 0},
		{value: "0.0001", want: 1},
		{value: "1ms", want: 1},
		{value: "1.25", want: 1250},
		{value: "-1", wantErr: true},
		{value: "banana", wantErr: true},
		{value: "5000000", wantErr: true},
	}
	for _, tc := range tests {
		t.Run(tc.value, func(t *testing.T) {
			got, err := windowsTimeoutMillis(tc.value)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("windowsTimeoutMillis(%q) succeeded with %d", tc.value, got)
				}
				return
			}
			if err != nil || got != tc.want {
				t.Fatalf("windowsTimeoutMillis(%q)=%d, %v; want %d", tc.value, got, err, tc.want)
			}
		})
	}
}

func TestApplyUDPConnOptsWindowsTimeos(t *testing.T) {
	c, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })

	apply := func(specText string, rcvWant, sndWant int) {
		t.Helper()
		spec, err := parse.ParseSpec(specText)
		if err != nil {
			t.Fatal(err)
		}
		if err := ApplyUDPConnOpts(c, spec, "udp4"); err != nil {
			t.Fatal(err)
		}
		for _, tc := range []struct {
			name string
			opt  int
			want int
		}{
			{name: "receive", opt: soRcvtimeo, want: rcvWant},
			{name: "send", opt: soSndtimeo, want: sndWant},
		} {
			t.Run(tc.name, func(t *testing.T) {
				got, err := windowsSocketOption(c, tc.opt)
				if err != nil {
					t.Fatal(err)
				}
				if got != tc.want {
					t.Fatalf("timeout=%dms want %dms", got, tc.want)
				}
			})
		}
	}

	apply("UDP:127.0.0.1:9,rcvtimeo=1.25,sndtimeo=2.5", 1250, 2500)
	apply("UDP:127.0.0.1:9,rcvtimeo=0,sndtimeo=0", 0, 0)
}

func TestApplyTCPConnOptsWindowsTTLAndTOS(t *testing.T) {
	ln, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	accepted := make(chan *net.TCPConn, 1)
	go func() {
		conn, _ := ln.AcceptTCP()
		accepted <- conn
	}()
	client, err := net.DialTCP("tcp4", nil, ln.Addr().(*net.TCPAddr))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close() })
	server := <-accepted
	t.Cleanup(func() { _ = server.Close() })
	spec, err := parse.ParseSpec("TCP4:127.0.0.1:1,ip-ttl=9,ip-tos=0x10")
	if err != nil {
		t.Fatal(err)
	}
	if err := ApplyTCPConnOpts(spec, client); err != nil {
		t.Fatal(err)
	}
	raw, err := client.SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	var ttl, tos int
	var optionErr error
	controlErr := raw.Control(func(fd uintptr) {
		ttl, optionErr = windows.GetsockoptInt(windows.Handle(fd), windows.IPPROTO_IP, windows.IP_TTL)
		if optionErr == nil {
			tos, optionErr = windows.GetsockoptInt(windows.Handle(fd), windows.IPPROTO_IP, windows.IP_TOS)
		}
	})
	if err := errors.Join(controlErr, optionErr); err != nil {
		t.Fatal(err)
	}
	if ttl != 9 {
		t.Fatalf("IP_TTL=%d want 9", ttl)
	}
	if tos != 0x10 {
		t.Fatalf("IP_TOS=%#x want %#x", tos, 0x10)
	}
}

func TestApplyListenBacklogWindows(t *testing.T) {
	ln, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	if err := ApplyListenBacklog(ln, 3); err != nil {
		t.Fatal(err)
	}
}

func windowsSocketOption(c *net.UDPConn, opt int) (int, error) {
	raw, err := c.SyscallConn()
	if err != nil {
		return 0, err
	}
	var value int
	var optionErr error
	controlErr := raw.Control(func(fd uintptr) {
		value, optionErr = windows.GetsockoptInt(windows.Handle(fd), solSocket, opt)
	})
	return value, errors.Join(controlErr, optionErr)
}
