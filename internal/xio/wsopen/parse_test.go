package wsopen

import (
	"testing"

	"github.com/oittaa/socat/internal/parse"
)

func TestWSTargetConnect(t *testing.T) {
	s, err := parse.ParseSpec("WS:example.com:80/echo/v1")
	if err != nil {
		t.Fatal(err)
	}
	host, port, path, err := wsTarget(s, false)
	if err != nil {
		t.Fatal(err)
	}
	if host != "example.com" || port != "80" || path != "/echo/v1" {
		t.Fatalf("got host=%q port=%q path=%q", host, port, path)
	}
}

func TestWSTargetPathOption(t *testing.T) {
	s, err := parse.ParseSpec("WS:127.0.0.1:9,path=/foo")
	if err != nil {
		t.Fatal(err)
	}
	_, _, path, err := wsTarget(s, false)
	if err != nil {
		t.Fatal(err)
	}
	if path != "/foo" {
		t.Fatalf("path=%q", path)
	}
}

func TestWSTargetListen(t *testing.T) {
	s, err := parse.ParseSpec("WS-LISTEN:8080/echo")
	if err != nil {
		t.Fatal(err)
	}
	_, port, path, err := wsTarget(s, true)
	if err != nil {
		t.Fatal(err)
	}
	if port != "8080" || path != "/echo" {
		t.Fatalf("port=%q path=%q", port, path)
	}
}

func TestWSScheme(t *testing.T) {
	s, _ := parse.ParseSpec("WSS:h:443")
	if wsScheme(s) != "wss" {
		t.Fatal(wsScheme(s))
	}
}

func TestWSTargetDefaultPath(t *testing.T) {
	s, err := parse.ParseSpec("WS:127.0.0.1:80")
	if err != nil {
		t.Fatal(err)
	}
	_, _, path, err := wsTarget(s, false)
	if err != nil {
		t.Fatal(err)
	}
	if path != "/" {
		t.Fatalf("path=%q", path)
	}
}

func TestWSTargetExtraParams(t *testing.T) {
	s, err := parse.ParseSpec("WS:example.com:80:echo:v1")
	if err != nil {
		t.Fatal(err)
	}
	host, port, path, err := wsTarget(s, false)
	if err != nil {
		t.Fatal(err)
	}
	if host != "example.com" || port != "80" || path != "/echo/v1" {
		t.Fatalf("got host=%q port=%q path=%q", host, port, path)
	}
}

func TestWSTargetListenExtraParams(t *testing.T) {
	s, err := parse.ParseSpec("WS-LISTEN:8080:echo")
	if err != nil {
		t.Fatal(err)
	}
	_, port, path, err := wsTarget(s, true)
	if err != nil {
		t.Fatal(err)
	}
	if port != "8080" || path != "/echo" {
		t.Fatalf("port=%q path=%q", port, path)
	}
}

func TestWSTargetIPv6(t *testing.T) {
	s, err := parse.ParseSpec("WS:[::1]:443/echo")
	if err != nil {
		t.Fatal(err)
	}
	host, port, path, err := wsTarget(s, false)
	if err != nil {
		t.Fatal(err)
	}
	if host != "[::1]" || port != "443" || path != "/echo" {
		t.Fatalf("got host=%q port=%q path=%q", host, port, path)
	}
}

func TestWSTargetListenRequiresPort(t *testing.T) {
	s, err := parse.ParseSpec("WS-LISTEN")
	if err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := wsTarget(s, true); err == nil {
		t.Fatal("expected error")
	}
}

func TestWSTargetConnectRequiresHostPort(t *testing.T) {
	s, err := parse.ParseSpec("WS:onlyhost")
	if err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := wsTarget(s, false); err == nil {
		t.Fatal("expected error")
	}
}
