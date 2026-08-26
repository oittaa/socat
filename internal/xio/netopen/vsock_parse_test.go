package netopen

import (
	"strings"
	"testing"

	"github.com/oittaa/socat/internal/parse"
)

func TestParseVsockU32(t *testing.T) {
	t.Parallel()
	cases := []struct {
		in      string
		want    uint32
		wantErr bool
	}{
		{in: "", want: 0},
		{in: "0", want: 0},
		{in: "1234", want: 1234},
		{in: "010", want: 8},
		{in: "0x10", want: 16},
		{in: "-1", want: vsockCIDAny},
		{in: "4294967295", want: vsockCIDAny},
		{in: "1junk", wantErr: true},
	}
	for _, tc := range cases {
		got, err := parseVsockU32(tc.in)
		if tc.wantErr {
			if err == nil {
				t.Errorf("parseVsockU32(%q) succeeded", tc.in)
			}
			continue
		}
		if err != nil {
			t.Errorf("parseVsockU32(%q): %v", tc.in, err)
			continue
		}
		if got != tc.want {
			t.Errorf("parseVsockU32(%q)=%d want %d", tc.in, got, tc.want)
		}
	}
}

func TestParseVsockCIDEmptyIsAny(t *testing.T) {
	t.Parallel()
	cid, err := parseVsockCID("")
	if err != nil {
		t.Fatal(err)
	}
	if cid != vsockCIDAny {
		t.Fatalf("empty cid=%d want ANY", cid)
	}
}

func TestParseVsockConnectParams(t *testing.T) {
	t.Parallel()
	s, err := parse.ParseSpec("VSOCK-CONNECT:1:0x22")
	if err != nil {
		t.Fatal(err)
	}
	ep, err := parseVsockConnectParams(s)
	if err != nil {
		t.Fatal(err)
	}
	if ep.cid != 1 || ep.port != 0x22 {
		t.Fatalf("got %+v", ep)
	}
	if _, err := parseVsockConnectParams(parse.Spec{Type: "VSOCK-CONNECT", Params: []string{"1"}}); err == nil {
		t.Fatal("expected error for missing port")
	}
}

func TestParseVsockBindOption(t *testing.T) {
	t.Parallel()
	connectSpec := func(bind string) parse.Spec {
		s, err := parse.ParseSpec("VSOCK-CONNECT:2:9,bind=" + bind)
		if err != nil {
			t.Fatal(err)
		}
		return s
	}
	t.Run("cid-only", func(t *testing.T) {
		ep, set, err := parseVsockBindOption(connectSpec("5555"), true)
		if err != nil || !set {
			t.Fatalf("set=%v err=%v", set, err)
		}
		if ep.cid != 5555 || ep.port != vsockPortAny {
			t.Fatalf("got %+v", ep)
		}
	})
	t.Run("port-only", func(t *testing.T) {
		ep, set, err := parseVsockBindOption(connectSpec(":5555"), true)
		if err != nil || !set {
			t.Fatalf("set=%v err=%v", set, err)
		}
		if ep.cid != vsockCIDAny || ep.port != 5555 {
			t.Fatalf("got %+v", ep)
		}
	})
	t.Run("cid-and-port", func(t *testing.T) {
		ep, set, err := parseVsockBindOption(connectSpec("1:9"), true)
		if err != nil || !set {
			t.Fatalf("set=%v err=%v", set, err)
		}
		if ep.cid != 1 || ep.port != 9 {
			t.Fatalf("got %+v", ep)
		}
	})
	t.Run("listen-rejects-port", func(t *testing.T) {
		s, err := parse.ParseSpec("VSOCK-LISTEN:9,bind=:1")
		if err != nil {
			t.Fatal(err)
		}
		_, _, err = parseVsockBindOption(s, false)
		if err == nil || !strings.Contains(err.Error(), "port specification not allowed") {
			t.Fatalf("err=%v", err)
		}
	})
	t.Run("listen-cid-only", func(t *testing.T) {
		s, err := parse.ParseSpec("VSOCK-LISTEN:9,bind=3")
		if err != nil {
			t.Fatal(err)
		}
		ep, set, err := parseVsockBindOption(s, false)
		if err != nil || !set {
			t.Fatalf("set=%v err=%v", set, err)
		}
		if ep.cid != 3 {
			t.Fatalf("cid=%d", ep.cid)
		}
	})
}
