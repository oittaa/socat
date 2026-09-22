package xio_test

import (
	"fmt"
	"strings"
	"testing"

	"github.com/oittaa/socat/internal/parse"
	"github.com/oittaa/socat/internal/xio"
	_ "github.com/oittaa/socat/internal/xio/all"
)

func TestAddressParameterCount(t *testing.T) {
	t.Parallel()
	cases := []struct {
		addr string
		want string
	}{
		{addr: "TCP:127.0.0.1:1:extra", want: "TCP: wrong number of parameters (3 instead of 2)"},
		{addr: "tcp:127.0.0.1:9:extra", want: "TCP: wrong number of parameters (3 instead of 2)"},
		{addr: "TCP:127.0.0.1", want: "TCP: wrong number of parameters (1 instead of 2)"},
		{addr: "TCP", want: "TCP: wrong number of parameters (0 instead of 2)"},
		{addr: "TCP:[::1]:80", want: ""},
		{addr: "TCP:127.0.0.1:9", want: ""},
		{addr: "TCP-LISTEN:1:2", want: "TCP-LISTEN: wrong number of parameters (2 instead of 1)"},
		{addr: "TCP-LISTEN", want: "TCP-LISTEN: wrong number of parameters (0 instead of 1)"},
		{addr: "TCP-LISTEN:9", want: ""},
		{addr: "TCP-L:9:extra", want: "TCP-L: wrong number of parameters (2 instead of 1)"},
		{addr: "INET:127.0.0.1:9:extra", want: "INET: wrong number of parameters (3 instead of 2)"},
		{addr: "UDP:127.0.0.1:9:extra", want: "UDP: wrong number of parameters (3 instead of 2)"},
		{addr: "UDP-RECV", want: "UDP-RECV: wrong number of parameters (0 instead of 1)"},
		{addr: "UDP-RECV:9", want: ""},
		{addr: "SCTP:127.0.0.1:9:extra", want: "SCTP: wrong number of parameters (3 instead of 2)"},
		{addr: "OPENSSL:127.0.0.1:9:extra", want: "OPENSSL: wrong number of parameters (3 instead of 2)"},
		{addr: "OPENSSL:127.0.0.1:9", want: ""},
		{addr: "OPENSSL-LISTEN", want: "OPENSSL-LISTEN: wrong number of parameters (0 instead of 1)"},
		{addr: "TLS:127.0.0.1:443:extra", want: "TLS: wrong number of parameters (3 instead of 2)"},
		{addr: "PTY:x", want: "PTY: wrong number of parameters (1 instead of 0)"},
		{addr: "PTY", want: ""},
		{addr: "STALL:x", want: "STALL: wrong number of parameters (1 instead of 0)"},
		{addr: "STDIO:x", want: "STDIO: wrong number of parameters (1 instead of 0)"},
		{addr: "STDIO", want: ""},
		{addr: "FD", want: "FD: wrong number of parameters (0 instead of 1)"},
		{addr: "FD:1:2", want: "FD: wrong number of parameters (2 instead of 1)"},
		{addr: "ACCEPT-FD", want: "ACCEPT-FD: wrong number of parameters (0 instead of 1)"},
		{addr: "EXEC", want: "EXEC: wrong number of parameters (0 instead of 1)"},
		{addr: "EXEC:echo hello", want: ""},
		{addr: "EXEC:echo:hello", want: "EXEC: wrong number of parameters (2 instead of 1)"},
		{addr: "SYSTEM", want: "SYSTEM: wrong number of parameters (0 instead of 1)"},
		{addr: "SYSTEM:echo hello", want: ""},
		{addr: "SHELL", want: ""},
		{addr: "SHELL:echo hi", want: ""},
		{addr: "SHELL:a:b", want: "SHELL: wrong number of parameters (2 instead of 0 or 1)"},
		{addr: "PIPE", want: ""},
		{addr: "PIPE:name", want: ""},
		{addr: "TUN", want: ""},
		{addr: "TUN:10.0.0.1/24:extra", want: "TUN: wrong number of parameters (2 instead of 0 or 1)"},
		{addr: "PROXY:a:b", want: "PROXY: wrong number of parameters (2 instead of 3)"},
		{addr: "PROXY:a:b:c", want: ""},
		{addr: "PROXY:a:b:c:d", want: "PROXY: wrong number of parameters (4 instead of 3)"},
		{addr: "SOCKS4:a:b:c:d", want: "SOCKS4: wrong number of parameters (4 instead of 3)"},
		{addr: "SOCKS5:a:b", want: "SOCKS5: wrong number of parameters (2 instead of 3 or 4)"},
		{addr: "SOCKS5:a:b:c", want: ""},
		{addr: "SOCKS5:a:1:b:c", want: ""},
		{addr: "SOCKS5:a:b:c:d:e", want: "SOCKS5: wrong number of parameters (5 instead of 3 or 4)"},
		{addr: "WS:example.com", want: "WS: wrong number of parameters (1 instead of 2 or more)"},
		{addr: "WS:example.com:80", want: ""},
		{addr: "WS:example.com:80:echo:v1", want: ""},
		{addr: "WS-LISTEN", want: "WS-LISTEN: wrong number of parameters (0 instead of 1 or more)"},
		{addr: "WS-LISTEN:8080:echo", want: ""},
		{addr: "SOCKET-CONNECT:2:6", want: "SOCKET-CONNECT: wrong number of parameters (2 instead of 3)"},
		{addr: "SOCKET-CONNECT:2:6:x00:extra", want: "SOCKET-CONNECT: wrong number of parameters (4 instead of 3)"},
		{addr: "VSOCK:1", want: "VSOCK: wrong number of parameters (1 instead of 2)"},
		{addr: "VSOCK-LISTEN", want: "VSOCK-LISTEN: wrong number of parameters (0 instead of 1)"},
		{addr: "IP-SENDTO:127.0.0.1:1:extra", want: "IP-SENDTO: wrong number of parameters (3 instead of 2)"},
		{addr: "POSIXMQ:/q:extra", want: "POSIXMQ: wrong number of parameters (2 instead of 1)"},
		{addr: "QUIC:127.0.0.1:443:extra", want: "QUIC: wrong number of parameters (3 instead of 2)"},
	}
	for _, tc := range cases {
		t.Run(tc.addr, func(t *testing.T) {
			spec, err := parse.ParseSpec(tc.addr)
			if err != nil {
				t.Fatal(err)
			}
			_, err = xio.PrepareSpec(spec)
			if tc.want == "" {
				if err != nil && strings.Contains(err.Error(), "wrong number of parameters") {
					t.Fatalf("valid address rejected: %v", err)
				}
				return
			}
			if err == nil || err.Error() != tc.want {
				t.Fatalf("err=%v want %q", err, tc.want)
			}
		})
	}
}

func TestParameterCountBeforeOptionValues(t *testing.T) {
	spec, err := parse.ParseSpec("TCP:127.0.0.1:1:extra,retry=x")
	if err != nil {
		t.Fatal(err)
	}
	_, err = xio.PrepareSpec(spec)
	const want = "TCP: wrong number of parameters (3 instead of 2)"
	if err == nil || err.Error() != want {
		t.Fatalf("err=%v want %q", err, want)
	}

	spec, err = parse.ParseSpec("TCP:127.0.0.1:1:extra,not-an-option")
	if err != nil {
		t.Fatal(err)
	}
	_, err = xio.PrepareSpec(spec)
	if err == nil || !strings.Contains(err.Error(), "unknown option") {
		t.Fatalf("err=%v want unknown option", err)
	}
}

func TestEveryAddressParameterCount(t *testing.T) {
	for _, reg := range xio.AddressRegistrations() {
		t.Run(reg.Name, func(t *testing.T) {
			min, max := reg.ParamMin, reg.ParamMax
			if max >= 0 {
				assertParamCount(t, reg.Name, max+1, wantParamCount(reg.Name, max+1, min, max))
			} else if err := prepareParams(t, reg.Name, min+4); err != nil && strings.Contains(err.Error(), "wrong number of parameters") {
				t.Fatalf("extra parameters rejected: %v", err)
			}
			if min > 0 {
				assertParamCount(t, reg.Name, min-1, wantParamCount(reg.Name, min-1, min, max))
			}
			if err := prepareParams(t, reg.Name, min); err != nil && strings.Contains(err.Error(), "wrong number of parameters") {
				t.Fatalf("minimum count %d rejected: %v", min, err)
			}
			if max > min {
				if err := prepareParams(t, reg.Name, max); err != nil && strings.Contains(err.Error(), "wrong number of parameters") {
					t.Fatalf("maximum count %d rejected: %v", max, err)
				}
			}
		})
	}
}

func TestAliasParameterCountMatchesTarget(t *testing.T) {
	regs := map[string]xio.AddressRegistration{}
	for _, reg := range xio.AddressRegistrations() {
		regs[reg.Name] = reg
	}
	for alias, dest := range xio.AddressAliasMap() {
		target, ok := regs[dest]
		if !ok {
			t.Errorf("alias %s -> %s is not registered", alias, dest)
			continue
		}
		n := target.ParamMin - 1
		if target.ParamMin == 0 {
			if target.ParamMax < 0 {
				continue
			}
			n = target.ParamMax + 1
		}
		err := prepareParams(t, alias, n)
		want := wantParamCount(alias, n, target.ParamMin, target.ParamMax)
		if err == nil || err.Error() != want {
			t.Errorf("%s: err=%v want %q", alias, err, want)
		}
	}
}

func assertParamCount(t *testing.T, name string, n int, want string) {
	t.Helper()
	if want == "" {
		return
	}
	err := prepareParams(t, name, n)
	if err == nil || err.Error() != want {
		t.Fatalf("%s x%d: err=%v want %q", name, n, err, want)
	}
}

func prepareParams(t *testing.T, name string, n int) error {
	t.Helper()
	if n < 0 {
		n = 0
	}
	_, err := xio.PrepareSpec(parse.Spec{Type: name, Params: repeatParam(n)})
	return err
}

func repeatParam(n int) []string {
	if n <= 0 {
		return nil
	}
	out := make([]string, n)
	for i := range out {
		out[i] = "x"
	}
	return out
}

func wantParamCount(name string, got, min, max int) string {
	var expect string
	switch {
	case max < 0:
		expect = fmt.Sprintf("%d or more", min)
	case min == max:
		expect = fmt.Sprintf("%d", min)
	default:
		expect = fmt.Sprintf("%d or %d", min, max)
	}
	return fmt.Sprintf("%s: wrong number of parameters (%d instead of %s)", name, got, expect)
}
