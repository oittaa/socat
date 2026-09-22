package xio_test

import (
	"strings"
	"testing"

	"github.com/oittaa/socat/internal/parse"
	"github.com/oittaa/socat/internal/xio"
	_ "github.com/oittaa/socat/internal/xio/all"
)

func TestAddressParameterCount(t *testing.T) {
	t.Parallel()
	cases := []struct {
		addr    string
		usage   string // empty when the parameter count is valid
		instead string // pinned "(N instead of M)" when set
	}{
		{addr: "TCP:127.0.0.1:1:extra", usage: "TCP:<host>:<port>", instead: "(3 instead of 2)"},
		{addr: "tcp:127.0.0.1:9:extra", usage: "tcp:<host>:<port>", instead: "(3 instead of 2)"},
		{addr: "TCP:127.0.0.1", usage: "TCP:<host>:<port>", instead: "(1 instead of 2)"},
		{addr: "TCP", usage: "TCP:<host>:<port>"},
		{addr: "TCP:[::1]:80"},
		{addr: "TCP:127.0.0.1:9"},
		{addr: "TCP-LISTEN:1:2", usage: "TCP-LISTEN:<port>", instead: "(2 instead of 1)"},
		{addr: "TCP-LISTEN", usage: "TCP-LISTEN:<port>"},
		{addr: "TCP-LISTEN:9"},
		{addr: "TCP-L:9:extra", usage: "TCP-L:<port>"},
		{addr: "INET:127.0.0.1:9:extra", usage: "INET:<host>:<port>"},
		{addr: "UDP:127.0.0.1:9:extra", usage: "UDP:<host>:<port>"},
		{addr: "UDP-RECV", usage: "UDP-RECV:<port>"},
		{addr: "UDP-RECV:9"},
		{addr: "SCTP:127.0.0.1:9:extra", usage: "SCTP:<host>:<port>"},
		{addr: "OPENSSL:127.0.0.1:9:extra", usage: "OPENSSL:<host>:<port>", instead: "(3 instead of 2)"},
		{addr: "OPENSSL:127.0.0.1:9"},
		{addr: "OPENSSL-LISTEN", usage: "OPENSSL-LISTEN:<port>", instead: "(0 instead of 1)"},
		{addr: "TLS:127.0.0.1:443:extra", usage: "TLS:<host>:<port>"},
		{addr: "PTY:x", usage: "PTY", instead: "(1 instead of 0)"},
		{addr: "PTY"},
		{addr: "STALL:x", usage: "STALL"},
		{addr: "STDIO:x", usage: "STDIO"},
		{addr: "STDIO"},
		{addr: "FD", usage: "FD:<fdnum>", instead: "(0 instead of 1)"},
		{addr: "FD:1:2", usage: "FD:<fdnum>", instead: "(2 instead of 1)"},
		{addr: "ACCEPT-FD", usage: "ACCEPT-FD:<fdnum>"},
		{addr: "EXEC", usage: "EXEC:<command-line>"},
		{addr: "EXEC:echo hello"},
		{addr: "EXEC:echo:hello", usage: "EXEC:<command-line>"},
		{addr: "SYSTEM", usage: "SYSTEM:<shell-command>"},
		{addr: "SYSTEM:echo hello"},
		{addr: "SHELL"},
		{addr: "SHELL:echo hi"},
		{addr: "SHELL:a:b", usage: "SHELL[:<shell-command>]"},
		{addr: "PIPE"},
		{addr: "PIPE:name"},
		{addr: "ECHO"},
		{addr: "ECHO:name"},
		{addr: "ECHO:a:b"},
		{addr: "TUN"},
		{addr: "TUN:10.0.0.1/24:extra", usage: "TUN[:<ip>/<bits>]"},
		{addr: "PROXY:a:b", usage: "PROXY:<proxy>:<host>:<port>"},
		{addr: "PROXY:a:b:c"},
		{addr: "PROXY:a:b:c:d", usage: "PROXY:<proxy>:<host>:<port>"},
		{addr: "SOCKS4:a:b:c:d", usage: "SOCKS4:<socks>:<host>:<port>"},
		{addr: "SOCKS5:a:b", usage: "SOCKS5:<socks-server>[:<socks-port>]:<target-host>:<target-port>", instead: "(2 instead of 3 or 4)"},
		{addr: "SOCKS5:a:b:c"},
		{addr: "SOCKS5:a:1:b:c"},
		{addr: "SOCKS5:a:b:c:d:e", usage: "SOCKS5:<socks-server>[:<socks-port>]:<target-host>:<target-port>", instead: "(5 instead of 3 or 4)"},
		{addr: "WS:example.com", usage: "WS:<host>:<port>", instead: "(1 instead of 2 or more)"},
		{addr: "WS:example.com:80"},
		{addr: "WS:example.com:80:echo:v1"},
		{addr: "WS-LISTEN", usage: "WS-LISTEN:<port>", instead: "(0 instead of 1 or more)"},
		{addr: "WS-LISTEN:8080:echo"},
		{addr: "SOCKET-CONNECT:2:6", usage: "SOCKET-CONNECT:<domain>:<protocol>:<remote-address>", instead: "(2 instead of 3)"},
		{addr: "SOCKET-CONNECT:2:6:x00:extra", usage: "SOCKET-CONNECT:<domain>:<protocol>:<remote-address>", instead: "(4 instead of 3)"},
		{addr: "VSOCK:1", usage: "VSOCK:<cid>:<port>"},
		{addr: "VSOCK-LISTEN", usage: "VSOCK-LISTEN:<port>"},
		{addr: "IP-SENDTO:127.0.0.1:1:extra", usage: "IP-SENDTO:<host>:<protocol>"},
		{addr: "POSIXMQ:/q:extra", usage: "POSIXMQ:<mqname>"},
		{addr: "QUIC:127.0.0.1:443:extra", usage: "QUIC:<host>:<port>"},
	}
	for _, tc := range cases {
		t.Run(tc.addr, func(t *testing.T) {
			spec, err := parse.ParseSpec(tc.addr)
			if err != nil {
				t.Fatal(err)
			}
			_, err = xio.PrepareSpec(spec)
			if tc.usage == "" {
				if err != nil && strings.Contains(err.Error(), "wrong number of parameters") {
					t.Fatalf("valid address rejected: %v", err)
				}
				return
			}
			assertParamCountError(t, err, tc.usage, tc.instead)
		})
	}
}

func TestParameterCountBeforeOptionValues(t *testing.T) {
	spec, err := parse.ParseSpec("TCP:127.0.0.1:1:extra,not-an-option")
	if err != nil {
		t.Fatal(err)
	}
	_, err = xio.PrepareSpec(spec)
	if err == nil || !strings.Contains(err.Error(), "unknown option") {
		t.Fatalf("err=%v want unknown option", err)
	}

	spec, err = parse.ParseSpec("TCP:127.0.0.1:1:extra,retry=x")
	if err != nil {
		t.Fatal(err)
	}
	_, err = xio.PrepareSpec(spec)
	if err == nil || !strings.Contains(err.Error(), "invalid retry") || strings.Contains(err.Error(), "wrong number of parameters") {
		t.Fatalf("err=%v want invalid retry before parameter count", err)
	}

	spec, err = parse.ParseSpec("TCP:127.0.0.1:1:extra")
	if err != nil {
		t.Fatal(err)
	}
	_, err = xio.PrepareSpec(spec)
	assertParamCountError(t, err, "TCP:<host>:<port>", "(3 instead of 2)")
}

func TestSocketOptionValueBeforeParameterCount(t *testing.T) {
	cases := []struct {
		addr string
		want string
	}{
		{addr: "SOCKET-CONNECT:2:6:x:extra,pf=bogus", want: "unknown protocol family"},
		{addr: "SOCKET-CONNECT:2:6:x:extra,protocol=nope", want: "invalid protocol"},
		{addr: "SOCKET-CONNECT:2:6:x:extra,bind=X", want: "syntax error"},
		{addr: "VSOCK:1:2:extra,pf=bogus", want: "unknown protocol family"},
		{addr: "VSOCK:1:2:extra,protocol=nope", want: "invalid protocol"},
		{addr: "VSOCK:1:2:extra,bind=1:bad", want: "bind:"},
	}
	for _, tc := range cases {
		t.Run(tc.addr, func(t *testing.T) {
			spec, err := parse.ParseSpec(tc.addr)
			if err != nil {
				t.Fatal(err)
			}
			_, err = xio.PrepareSpec(spec)
			if err == nil || !strings.Contains(err.Error(), tc.want) || strings.Contains(err.Error(), "wrong number of parameters") {
				t.Fatalf("err=%v want %s before parameter count", err, tc.want)
			}
		})
	}
}

func TestRegisteredParameterCounts(t *testing.T) {
	got := map[string]xio.AddressRegistration{}
	for _, reg := range xio.AddressRegistrations() {
		if _, dup := got[reg.Name]; dup {
			t.Errorf("duplicate registration %s", reg.Name)
		}
		got[reg.Name] = reg
	}
	for name, want := range expectedAddressParams {
		reg, ok := got[name]
		if !ok {
			t.Errorf("missing registration %s", name)
			continue
		}
		if reg.ParamMin != want[0] || reg.ParamMax != want[1] {
			t.Errorf("%s: registry %d..%d want %d..%d", name, reg.ParamMin, reg.ParamMax, want[0], want[1])
		}
		assertCountBounds(t, name, want[0], want[1])
	}
	for name := range got {
		if _, ok := expectedAddressParams[name]; !ok {
			t.Errorf("unexpected registration %s", name)
		}
	}
}

func TestAliasParameterCounts(t *testing.T) {
	regs := map[string]xio.AddressRegistration{}
	for _, reg := range xio.AddressRegistrations() {
		regs[reg.Name] = reg
	}
	aliases := xio.AddressAliasMap()
	for alias, want := range expectedAliasParams {
		dest, ok := aliases[alias]
		if !ok {
			t.Errorf("missing alias %s", alias)
			continue
		}
		target, ok := expectedAddressParams[dest]
		if !ok || target != want {
			t.Errorf("alias %s -> %s: table %v target %v", alias, dest, want, target)
		}
		reg, ok := regs[dest]
		if !ok {
			t.Errorf("alias %s -> %s is not registered", alias, dest)
			continue
		}
		if reg.ParamMin != want[0] || reg.ParamMax != want[1] {
			t.Errorf("%s: resolved %d..%d want %d..%d", alias, reg.ParamMin, reg.ParamMax, want[0], want[1])
		}
		assertCountBounds(t, alias, want[0], want[1])
	}
	for alias := range aliases {
		if _, ok := expectedAliasParams[alias]; !ok {
			t.Errorf("unexpected alias %s", alias)
		}
	}
}

func assertCountBounds(t *testing.T, name string, min, max int) {
	t.Helper()
	if max >= 0 {
		err := prepareParams(t, name, max+1)
		if err == nil || !strings.Contains(err.Error(), "wrong number of parameters") {
			t.Errorf("%s: %d parameters: err=%v", name, max+1, err)
		}
	} else if err := prepareParams(t, name, min+4); err != nil && strings.Contains(err.Error(), "wrong number of parameters") {
		t.Errorf("%s: extra parameters rejected: %v", name, err)
	}
	if min > 0 {
		err := prepareParams(t, name, min-1)
		if err == nil || !strings.Contains(err.Error(), "wrong number of parameters") {
			t.Errorf("%s: %d parameters: err=%v", name, min-1, err)
		}
	}
	if err := prepareParams(t, name, min); err != nil && strings.Contains(err.Error(), "wrong number of parameters") {
		t.Errorf("%s: minimum %d rejected: %v", name, min, err)
	}
	if max > min {
		if err := prepareParams(t, name, max); err != nil && strings.Contains(err.Error(), "wrong number of parameters") {
			t.Errorf("%s: maximum %d rejected: %v", name, max, err)
		}
	}
}

func assertParamCountError(t *testing.T, err error, usage, instead string) {
	t.Helper()
	if err == nil {
		t.Fatal("expected a parameter-count error")
	}
	msg := err.Error()
	if !strings.Contains(msg, "wrong number of parameters") || !strings.Contains(msg, "usage: "+usage) {
		t.Fatalf("err=%v want wrong number of parameters and usage %s", err, usage)
	}
	if instead != "" && !strings.Contains(msg, instead) {
		t.Fatalf("err=%v want %s", err, instead)
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
