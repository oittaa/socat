package xio_test

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/oittaa/socat/internal/addrconfig"
	"github.com/oittaa/socat/internal/xio"
	_ "github.com/oittaa/socat/internal/xio/all"
)

func TestCreateUnknownUserDoesNotCreateFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "f")
	_, err := xio.OpenSpec(context.Background(), mustParseSpec(t, "CREATE:"+path+",user=nosuchuser"), xio.ModeWrite, nil)
	if err == nil || !strings.Contains(err.Error(), "no such user") {
		t.Fatalf("error=%v", err)
	}
	if _, statErr := os.Stat(path); !os.IsNotExist(statErr) {
		t.Fatalf("CREATE left %s behind: %v", path, statErr)
	}
}

func TestPrepareProtocolFamily(t *testing.T) {
	_, err := xio.PrepareSpec(mustParseSpec(t, "TCP4:127.0.0.1:9,pf=ipx"))
	if err == nil || !strings.Contains(err.Error(), "unknown protocol family") {
		t.Fatalf("pf=ipx error=%v", err)
	}
	_, err = xio.PrepareSpec(mustParseSpec(t, "TCP4:127.0.0.1:9,pf=4"))
	if err == nil || !strings.Contains(err.Error(), "not usable") {
		t.Fatalf("pf=4 error=%v", err)
	}

	ipv4, err := xio.PrepareSpec(mustParseSpec(t, "TCP4:127.0.0.1:9,pf=ip4"))
	if err != nil {
		t.Fatal(err)
	}
	if ipv4.Config.Network.IPFamily != addrconfig.IPFamilyIPv4 || ipv4.Config.Network.ProtocolFamily != 2 {
		t.Fatalf("pf=ip4 family=%v number=%d", ipv4.Config.Network.IPFamily, ipv4.Config.Network.ProtocolFamily)
	}
	numeric, err := xio.PrepareSpec(mustParseSpec(t, "TCP4:127.0.0.1:9,pf=2"))
	if err != nil {
		t.Fatal(err)
	}
	if numeric.Config.Network.IPFamily != addrconfig.IPFamilyIPv4 {
		t.Fatalf("pf=2 family=%v", numeric.Config.Network.IPFamily)
	}

	raw, err := xio.PrepareSpec(mustParseSpec(t, "SOCKET-LISTEN:2:0:x00007f000001,pf=4"))
	if err != nil {
		t.Fatal(err)
	}
	if !raw.Config.Network.ProtocolSet || raw.Config.Network.ProtocolFamily != 4 {
		t.Fatalf("SOCKET pf=%+v", raw.Config.Network)
	}
}

func TestPrepareRejectsInvalidSocktypeAndPTYInterval(t *testing.T) {
	_, err := xio.PrepareSpec(mustParseSpec(t, "TCP4:127.0.0.1:9,so-type=99"))
	if err == nil || !strings.Contains(err.Error(), "unsupported") {
		t.Fatalf("so-type error=%v", err)
	}
	if _, err := xio.PrepareSpec(mustParseSpec(t, "TCP4:127.0.0.1:9,so-type=1")); err != nil {
		t.Fatal(err)
	}
	_, err = xio.PrepareSpec(mustParseSpec(t, "PTY,pty-interval=abc"))
	if err == nil || !strings.Contains(err.Error(), "pty-interval") {
		t.Fatalf("pty-interval error=%v", err)
	}
}

func TestPrepareDecodesPortsOnce(t *testing.T) {
	for _, tc := range []struct {
		raw  string
		want string
	}{
		{"TCP4:127.0.0.1:99999", "invalid port"},
		{"TCP4:127.0.0.1:080", "invalid port"},
		{"TCP4:127.0.0.1:0b10", "invalid port"},
		{"TCP4:127.0.0.1:9,sourceport=080", `option "sourceport": invalid value`},
		{"TCP4:127.0.0.1:9,sourceport=99999", `option "sourceport": invalid value`},
	} {
		_, err := xio.PrepareSpec(mustParseSpec(t, tc.raw))
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Fatalf("%s: %v", tc.raw, err)
		}
	}
	prepared, err := xio.PrepareSpec(mustParseSpec(t, "TCP4:127.0.0.1:http,sourceport=0x50"))
	if err != nil {
		t.Fatal(err)
	}
	port := prepared.Config.Network.TargetPort
	source := prepared.Config.Network.SourcePort
	if port.Numeric || port.Service != "http" || !source.Numeric || source.Number != 80 || source.Text() != "0x50" {
		t.Fatalf("port=%+v source=%+v", port, source)
	}
}

func preparedOwner(t *testing.T, prepared xio.PreparedAddress, kind addrconfig.FileActionKind) addrconfig.OwnerRef {
	t.Helper()
	for _, action := range prepared.Config.File.Actions {
		if action.Kind == kind {
			return action.Owner
		}
	}
	t.Fatalf("missing file action %v", kind)
	return addrconfig.OwnerRef{}
}
