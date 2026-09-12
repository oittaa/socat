package xio

import (
	"testing"

	"github.com/oittaa/socat/internal/addrconfig"
	"github.com/oittaa/socat/internal/parse"
)

func TestNamedSocketIntAllowsSignedValues(t *testing.T) {
	s, err := parse.ParseSpec("TCP:127.0.0.1:9,tcp-linger2=-1")
	if err != nil {
		t.Fatal(err)
	}
	config, err := addrconfig.Decode(s, addrconfig.Facts{Type: "TCP"})
	if err != nil {
		t.Fatal(err)
	}
	got := namedSocketNumber(config, addrconfig.NamedSocketTCPLinger2)
	if !got.ok || got.n != -1 {
		t.Fatalf("tcp-linger2=-1 decoded as %+v", got)
	}
}

func TestBareSCTPNodelayIsOne(t *testing.T) {
	s, err := parse.ParseSpec("TCP:127.0.0.1:9,sctp-nodelay")
	if err != nil {
		t.Fatal(err)
	}
	config, err := addrconfig.Decode(s, addrconfig.Facts{Type: "TCP"})
	if err != nil {
		t.Fatal(err)
	}
	got := namedSocketNumber(config, addrconfig.NamedSocketSCTPNodelay)
	if !got.ok || got.n != 1 {
		t.Fatalf("bare sctp-nodelay decoded as %+v want 1", got)
	}
}

type namedSocketNumberResult struct {
	ok bool
	n  int
}

func namedSocketNumber(config addrconfig.Address, id addrconfig.NamedSocket) namedSocketNumberResult {
	for _, action := range config.Network.Actions {
		if action.Kind == addrconfig.SocketActionNamed && action.Named == id {
			return namedSocketNumberResult{ok: true, n: action.Number}
		}
	}
	return namedSocketNumberResult{}
}
