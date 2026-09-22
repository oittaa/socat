package xio_test

import (
	"strings"
	"testing"

	"github.com/oittaa/socat/internal/parse"
	"github.com/oittaa/socat/internal/xio"
	_ "github.com/oittaa/socat/internal/xio/all"
)

func TestTrailingColonParameterCount(t *testing.T) {
	t.Parallel()
	cases := []struct {
		addr    string
		params  int
		usage   string
		instead string
	}{
		{addr: "STDIO", params: 0},
		{addr: "STDIO:", params: 1, usage: "STDIO", instead: "(1 instead of 0)"},
		{addr: "PTY", params: 0},
		{addr: "PTY:", params: 1, usage: "PTY", instead: "(1 instead of 0)"},
		{addr: "STALL", params: 0},
		{addr: "STALL:", params: 1, usage: "STALL", instead: "(1 instead of 0)"},
		{addr: "SYSTEM", params: 0, usage: "SYSTEM:<shell-command>", instead: "(0 instead of 1)"},
		{addr: "SYSTEM:", params: 1},
		{addr: "SHELL", params: 0},
		{addr: "SHELL:", params: 1},
	}
	for _, tc := range cases {
		t.Run(tc.addr, func(t *testing.T) {
			spec, err := parse.ParseSpec(tc.addr)
			if err != nil {
				t.Fatal(err)
			}
			if len(spec.Params) != tc.params {
				t.Fatalf("params=%q want %d", spec.Params, tc.params)
			}
			_, err = xio.PrepareSpec(spec)
			if tc.usage == "" {
				if err != nil {
					t.Fatalf("accepted address: %v", err)
				}
				return
			}
			assertParamCountError(t, err, tc.usage, tc.instead)
		})
	}
}

func TestAddressParameterCount(t *testing.T) {
	t.Parallel()
	cases := []struct {
		addr    string
		usage   string
		instead string
	}{
		{addr: "TCP:127.0.0.1:1:extra", usage: "TCP:<host>:<port>", instead: "(3 instead of 2)"},
		{addr: "tcp:127.0.0.1:9:extra", usage: "tcp:<host>:<port>", instead: "(3 instead of 2)"},
		{addr: "TCP", usage: "TCP:<host>:<port>", instead: "(0 instead of 2)"},
		{addr: "TCP:", usage: "TCP:<host>:<port>", instead: "(1 instead of 2)"},
		{addr: "TCP:127.0.0.1:9"},
		{addr: "TCP-LISTEN:1:2", usage: "TCP-LISTEN:<port>", instead: "(2 instead of 1)"},
		{addr: "OPENSSL-LISTEN", usage: "OPENSSL-LISTEN:<port>", instead: "(0 instead of 1)"},
		{addr: "SOCKS5:a:b", usage: "SOCKS5:<socks-server>[:<socks-port>]:<target-host>:<target-port>", instead: "(2 instead of 3 or 4)"},
		{addr: "SOCKS5:a:b:c"},
		{addr: "SOCKS5:a:1:b:c"},
		{addr: "SOCKS5:a:b:c:d:e", usage: "SOCKS5:<socks-server>[:<socks-port>]:<target-host>:<target-port>", instead: "(5 instead of 3 or 4)"},
		{addr: "WS:example.com", usage: "WS:<host>:<port>", instead: "(1 instead of 2 or more)"},
		{addr: "WS:example.com:80:echo:v1"},
		{addr: "WS-LISTEN", usage: "WS-LISTEN:<port>", instead: "(0 instead of 1 or more)"},
		{addr: "SOCKET-CONNECT:2:6", usage: "SOCKET-CONNECT:<domain>:<protocol>:<remote-address>", instead: "(2 instead of 3)"},
		{addr: "SOCKET-CONNECT:2:6:x00:extra", usage: "SOCKET-CONNECT:<domain>:<protocol>:<remote-address>", instead: "(4 instead of 3)"},
		{addr: "ECHO"},
		{addr: "ECHO:name"},
		{addr: "ECHO:a:b"},
		{addr: "PIPE"},
		{addr: "EXEC:echo hello"},
		{addr: "EXEC:echo:hello", usage: "EXEC:<command-line>"},
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

	spec, err = parse.ParseSpec("TCP:127.0.0.1:1:x,tun-type=tap")
	if err != nil {
		t.Fatal(err)
	}
	_, err = xio.PrepareSpec(spec)
	if err == nil || !strings.Contains(err.Error(), `option "tun-type" not supported with this address type`) || strings.Contains(err.Error(), "wrong number of parameters") {
		t.Fatalf("err=%v want tun-type unsupported before parameter count", err)
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

func TestAddressParameterMetadata(t *testing.T) {
	regs := map[string]xio.AddressRegistration{}
	for _, reg := range xio.AddressRegistrations() {
		if _, dup := regs[reg.Name]; dup {
			t.Errorf("duplicate registration %s", reg.Name)
		}
		regs[reg.Name] = reg
		got, ok := xio.AddressRegistrationForType(reg.Name)
		if !ok || got.Name != reg.Name || got.ParamMin != reg.ParamMin || got.ParamMax != reg.ParamMax {
			t.Errorf("%s metadata %+v", reg.Name, got)
		}
	}
	if len(regs) == 0 {
		t.Fatal("no address registrations")
	}
	for alias, dest := range xio.AddressAliasMap() {
		if _, registered := regs[alias]; registered {
			t.Errorf("alias %s is registered separately", alias)
		}
		aliasReg, ok := xio.AddressRegistrationForType(alias)
		target, okTarget := xio.AddressRegistrationForType(dest)
		if !ok || !okTarget || aliasReg.Name != target.Name || aliasReg.ParamMin != target.ParamMin || aliasReg.ParamMax != target.ParamMax {
			t.Errorf("alias %s -> %s: %+v target %+v", alias, dest, aliasReg, target)
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
