package addrconfig

import (
	"testing"

	"github.com/oittaa/socat/internal/parse"
)

func TestPortTargetEmptyAndZero(t *testing.T) {
	empty := PortFromText("")
	if !empty.Empty() || empty.IsZero() {
		t.Fatalf("empty: %+v", empty)
	}

	zero := PortFromText("0")
	if zero.Empty() || !zero.IsZero() || zero.Text() != "0" {
		t.Fatalf("0: %+v text=%q", zero, zero.Text())
	}

	padded := PortFromText("00")
	if padded.Empty() || !padded.IsZero() || padded.Text() != "00" {
		t.Fatalf("00: %+v text=%q", padded, padded.Text())
	}

	port := PortFromText("80")
	if port.Empty() || port.IsZero() || port.Text() != "80" {
		t.Fatalf("80: %+v", port)
	}

	svc := PortFromText("http")
	if svc.Empty() || svc.IsZero() || svc.Numeric || svc.Text() != "http" {
		t.Fatalf("http: %+v", svc)
	}
}

func TestUNIXListenPathIsNotListenPort(t *testing.T) {
	spec, err := parse.ParseSpec("UNIX-LISTEN:/tmp/sock")
	if err != nil {
		t.Fatal(err)
	}
	got, err := Decode(spec, Facts{Type: "UNIX-LISTEN", Kind: AddressKindUNIX, Role: AddressRoleListen})
	if err != nil {
		t.Fatal(err)
	}
	if got.Network.ListenSet || !got.Network.ListenPort.Empty() {
		t.Fatalf("listen port set=%v %+v", got.Network.ListenSet, got.Network.ListenPort)
	}
	if len(got.Params) != 1 || got.Params[0] != "/tmp/sock" {
		t.Fatalf("params=%q", got.Params)
	}
}

func TestWebSocketPathPreparedOnce(t *testing.T) {
	decode := func(text string, role AddressRole) Address {
		t.Helper()
		spec, err := parse.ParseSpec(text)
		if err != nil {
			t.Fatal(err)
		}
		got, err := Decode(spec, Facts{Type: spec.Type, Kind: AddressKindWebSocket, Role: role})
		if err != nil {
			t.Fatal(err)
		}
		return got
	}

	got := decode("WS:127.0.0.1:80", AddressRoleConnect)
	if !got.TLS.WSPath.Set || got.TLS.WSPath.Value != "/" {
		t.Fatalf("default path=%+v", got.TLS.WSPath)
	}

	got = decode("WS:127.0.0.1:80,path=echo", AddressRoleConnect)
	if got.TLS.WSPath.Value != "/echo" {
		t.Fatalf("slash normalize=%q", got.TLS.WSPath.Value)
	}

	got = decode("WS:127.0.0.1:8080/service,path=", AddressRoleConnect)
	if got.TLS.WSPath.Value != "/service" {
		t.Fatalf("empty path= fallback=%q", got.TLS.WSPath.Value)
	}

	got = decode("WS-LISTEN:8080/echo,path=", AddressRoleListen)
	if got.TLS.WSPath.Value != "/echo" {
		t.Fatalf("listen empty path= fallback=%q", got.TLS.WSPath.Value)
	}
}
