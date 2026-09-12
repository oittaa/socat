package xio

import (
	"bytes"
	"context"
	"errors"
	"net"
	"strings"
	"testing"

	"github.com/oittaa/socat/internal/addrconfig"
	"github.com/oittaa/socat/internal/logx"
)

func TestWithNetNSNoOption(t *testing.T) {
	called := false
	err := WithNetNS("", nil, func() error {
		called = true
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if !called {
		t.Fatal("fn not called")
	}
}

func TestWithNetNSEmptyValue(t *testing.T) {
	called := false
	if err := WithNetNS("", nil, func() error { called = true; return nil }); err != nil {
		t.Fatal(err)
	}
	if !called {
		t.Fatal("fn not called")
	}
}

func TestWithNetNSExperimentalNoWarn(t *testing.T) {
	var buf bytes.Buffer
	log := logx.New()
	log.SetOutput(&buf)
	err := WithNetNS("socat-missing-ns", NewSession(Options{Experimental: true}, log), func() error {
		t.Fatal("fn must not run when ns is missing")
		return nil
	})
	if err == nil {
		t.Fatal("expected error")
	}
	if strings.Contains(buf.String(), "experimental") {
		t.Fatalf("unexpected warning:\n%s", buf.String())
	}
}

func TestNetNamespaceName(t *testing.T) {
	if netNamespaceName(addrconfig.Address{}) != "" {
		t.Fatal("empty config")
	}
	config := addrconfig.Address{Common: addrconfig.Common{NetNamespace: addrconfig.OptionalString{Set: true, Value: "foo"}}}
	if got := netNamespaceName(config); got != "foo" {
		t.Fatalf("got %q", got)
	}
}

func TestCloseConnWhenDonePreservesPacketConn(t *testing.T) {
	c, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	got := closeConnWhenDone(context.Background(), c)
	if _, ok := got.(net.PacketConn); !ok {
		t.Fatalf("%T is not net.PacketConn; Go DNS would use TCP framing on UDP", got)
	}
}

func TestLookupResolverPreferGoWithNetNS(t *testing.T) {
	plain := LookupResolver(addrconfig.Address{})
	if plain.PreferGo {
		t.Fatal("default resolver must not force PreferGo")
	}
	config := addrconfig.Address{Common: addrconfig.Common{NetNamespace: addrconfig.OptionalString{Set: true, Value: "foo"}}}
	r := LookupResolver(config)
	if r == nil || !r.PreferGo {
		t.Fatal("netns= must use PreferGo so DNS stays on the locked thread")
	}
	if r.Dial == nil {
		t.Fatal("netns= must Dial so in-flight DNS reads close on cancel")
	}
}

func TestLookupResolverLeavesDefaultResolverUnwrapped(t *testing.T) {
	before := net.DefaultResolver
	r := LookupResolver(addrconfig.Address{})
	if r != before {
		t.Fatal("empty spec must keep the process-global resolver")
	}
}

func TestWrapNetNSDialNoOption(t *testing.T) {
	called := false
	inner := func(context.Context) (net.Conn, error) {
		called = true
		return nil, errors.New("dialed")
	}
	got := WrapNetNSDial("", nil, inner)
	_, err := got(context.Background())
	if !called || err == nil || err.Error() != "dialed" {
		t.Fatalf("passthrough failed: called=%v err=%v", called, err)
	}
}
