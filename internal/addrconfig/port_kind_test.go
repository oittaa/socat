package addrconfig

import (
	"strings"
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
	if got.Network.SocketPath != "/tmp/sock" {
		t.Fatalf("unix path=%q", got.Network.SocketPath)
	}
}

func TestDecodeNamedFileAndPOSIXMQPaths(t *testing.T) {
	create, err := parse.ParseSpec("CREATE:out.txt")
	if err != nil {
		t.Fatal(err)
	}
	got, err := Decode(create, Facts{Type: "CREATE", Kind: AddressKindCREATE})
	if err != nil {
		t.Fatal(err)
	}
	if got.File.Path != "out.txt" {
		t.Fatalf("file path=%q", got.File.Path)
	}

	mq, err := parse.ParseSpec("POSIXMQ:/queue")
	if err != nil {
		t.Fatal(err)
	}
	got, err = Decode(mq, Facts{Type: "POSIXMQ", Kind: AddressKindPOSIXMQ})
	if err != nil {
		t.Fatal(err)
	}
	if got.Network.MQName != "/queue" {
		t.Fatalf("mq name=%q", got.Network.MQName)
	}
	if got.Network.ListenSet || !got.Network.ListenPort.Empty() || got.Network.TargetSet {
		t.Fatalf("POSIXMQ used host/port: listen=%v %+v target=%v", got.Network.ListenSet, got.Network.ListenPort, got.Network.TargetSet)
	}

	read, err := parse.ParseSpec("POSIXMQ-READ:/q")
	if err != nil {
		t.Fatal(err)
	}
	got, err = Decode(read, Facts{Type: "POSIXMQ-READ", Kind: AddressKindPOSIXMQ, Role: AddressRoleReceive})
	if err != nil {
		t.Fatal(err)
	}
	if got.Network.MQName != "/q" {
		t.Fatalf("read mq=%q", got.Network.MQName)
	}
	if got.Network.ListenSet || !got.Network.ListenPort.Empty() {
		t.Fatalf("POSIXMQ-READ listen port %+v", got.Network.ListenPort)
	}

	_, err = Decode(parse.Spec{Type: "POSIXMQ", Params: []string{"a", "b"}}, Facts{Type: "POSIXMQ", Kind: AddressKindPOSIXMQ})
	if err == nil || !strings.Contains(err.Error(), "too many parameters") {
		t.Fatalf("extra posixmq params: %v", err)
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
