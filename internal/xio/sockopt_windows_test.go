//go:build windows

package xio

import (
	"errors"
	"fmt"
	"net"
	"strings"
	"testing"
	"unsafe"

	"github.com/oittaa/socat/internal/parse"
	"github.com/oittaa/socat/internal/relay"
	"golang.org/x/sys/windows"
)

func TestApplyUDPConnOptsAppliesSetsockoptWindows(t *testing.T) {
	c, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	spec, err := parse.ParseSpec(fmt.Sprintf("UDP:127.0.0.1:9,setsockopt=%d:%d:1", solSocket, windows.SO_BROADCAST))
	if err != nil {
		t.Fatal(err)
	}
	if err := ApplyUDPConnOpts(c, spec, "udp4"); err != nil {
		t.Fatalf("UDP setsockopt must apply, not no-op: %v", err)
	}
	got, err := windowsSocketOption(c, windows.SO_BROADCAST)
	if err != nil {
		t.Fatal(err)
	}
	if got == 0 {
		t.Fatalf("SO_BROADCAST=%d want enabled", got)
	}
}

func TestApplyTCPConnOptsAppliesSetsockoptOnUDPWindows(t *testing.T) {
	c, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	spec, err := parse.ParseSpec(fmt.Sprintf("UDP:127.0.0.1:9,setsockopt-int=%d:%d:1", solSocket, windows.SO_BROADCAST))
	if err != nil {
		t.Fatal(err)
	}
	if err := ApplyTCPConnOpts(spec, c); err != nil {
		t.Fatalf("UDP setsockopt must apply, not no-op: %v", err)
	}
	got, err := windowsSocketOption(c, windows.SO_BROADCAST)
	if err != nil {
		t.Fatal(err)
	}
	if got == 0 {
		t.Fatalf("SO_BROADCAST=%d want enabled", got)
	}
}

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

func TestApplyUDPConnOptsAppliesLateWindows(t *testing.T) {
	c, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })

	spec, err := parse.ParseSpec("UDP:127.0.0.1:9,sndbuf-late=65536,rcvbuf-late=65536")
	if err != nil {
		t.Fatal(err)
	}
	if err := ApplyUDPConnOpts(c, spec, "udp4"); err != nil {
		t.Fatalf("ApplyUDPConnOpts: %v", err)
	}
	got, err := windowsSocketOption(c, windows.SO_SNDBUF)
	if err != nil {
		t.Fatal(err)
	}
	if got < 65536 {
		t.Fatalf("SO_SNDBUF=%d want >= 65536 after ApplyUDPConnOpts", got)
	}
	got, err = windowsSocketOption(c, windows.SO_RCVBUF)
	if err != nil {
		t.Fatal(err)
	}
	if got < 65536 {
		t.Fatalf("SO_RCVBUF=%d want >= 65536 after ApplyUDPConnOpts", got)
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

func TestApplySocketOptionsLingerWindows(t *testing.T) {
	c, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	spec, err := parse.ParseSpec("TCP-LISTEN:1,so-linger=3")
	if err != nil {
		t.Fatal(err)
	}
	raw, err := c.SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	var got struct {
		Onoff  uint16
		Linger uint16
	}
	var optionErr error
	controlErr := raw.Control(func(fd uintptr) {
		optionErr = ApplySocketOptions(int(fd), spec)
		if optionErr != nil {
			return
		}
		size := int32(unsafe.Sizeof(got))
		optionErr = windows.Getsockopt(windows.Handle(fd), int32(windows.SOL_SOCKET), int32(windows.SO_LINGER), (*byte)(unsafe.Pointer(&got)), &size)
	})
	if err := errors.Join(controlErr, optionErr); err != nil {
		t.Fatal(err)
	}
	if got.Onoff != 1 || got.Linger != 3 {
		t.Fatalf("SO_LINGER=%+v want enabled, 3 seconds", got)
	}
}

func windowsTCPSockopt(t *testing.T, c *net.TCPConn, opt int) int {
	t.Helper()
	raw, err := c.SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	var value int
	var optionErr error
	controlErr := raw.Control(func(fd uintptr) {
		value, optionErr = windows.GetsockoptInt(windows.Handle(fd), solSocket, opt)
	})
	if err := errors.Join(controlErr, optionErr); err != nil {
		t.Fatal(err)
	}
	return value
}

func TestApplySocketOptionsSndbufRcvbufWindows(t *testing.T) {
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

	spec, err := parse.ParseSpec("TCP:127.0.0.1:9,sndbuf=4096,rcvbuf=8192,sndbuf-late=65536")
	if err != nil {
		t.Fatal(err)
	}
	raw, err := client.SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	var optionErr error
	controlErr := raw.Control(func(fd uintptr) {
		optionErr = ApplySocketOptions(int(fd), spec)
	})
	if err := errors.Join(controlErr, optionErr); err != nil {
		t.Fatal(err)
	}
	if got := windowsTCPSockopt(t, client, windows.SO_SNDBUF); got < 4096 {
		t.Fatalf("SO_SNDBUF=%d want >= 4096", got)
	}
	if got := windowsTCPSockopt(t, client, windows.SO_RCVBUF); got < 8192 {
		t.Fatalf("SO_RCVBUF=%d want >= 8192", got)
	}
	if got := windowsTCPSockopt(t, client, windows.SO_SNDBUF); got >= 65536 {
		t.Fatalf("SO_SNDBUF=%d: sndbuf-late applied inside ApplySocketOptions", got)
	}
}

func TestWrapCommonAppliesSndbufLateOverEarlyWindows(t *testing.T) {
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

	spec, err := parse.ParseSpec("TCP:127.0.0.1:9,sndbuf=4096,sndbuf-late=65536")
	if err != nil {
		t.Fatal(err)
	}
	raw, err := client.SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	var optionErr error
	controlErr := raw.Control(func(fd uintptr) {
		optionErr = ApplySocketOptions(int(fd), spec)
	})
	if err := errors.Join(controlErr, optionErr); err != nil {
		t.Fatal(err)
	}
	early := windowsTCPSockopt(t, client, windows.SO_SNDBUF)
	if early < 4096 {
		t.Fatalf("early SO_SNDBUF=%d want >= 4096", early)
	}
	if _, err := WrapCommon(spec, relay.NetStream{Conn: client}); err != nil {
		t.Fatal(err)
	}
	late := windowsTCPSockopt(t, client, windows.SO_SNDBUF)
	if late < 65536 {
		t.Fatalf("SO_SNDBUF=%d want >= 65536 after WrapCommon (late wins)", late)
	}
}

func TestBindToDeviceUnsupportedWindows(t *testing.T) {
	c, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	spec, err := parse.ParseSpec("UDP:127.0.0.1:9,bindtodevice=lo")
	if err != nil {
		t.Fatal(err)
	}
	raw, err := c.SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	var optionErr error
	controlErr := raw.Control(func(fd uintptr) {
		optionErr = ApplySocketOptions(int(fd), spec)
	})
	if err := errors.Join(controlErr, optionErr); err == nil || !strings.Contains(err.Error(), "not supported") {
		t.Fatalf("error=%v want not supported", err)
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
