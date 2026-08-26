package netopen

import (
	"strings"
	"syscall"
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

func TestParseVsockSocketArgs(t *testing.T) {
	t.Parallel()
	must := func(spec string) parse.Spec {
		s, err := parse.ParseSpec(spec)
		if err != nil {
			t.Fatal(err)
		}
		return s
	}
	t.Run("defaults", func(t *testing.T) {
		args, err := parseVsockSocketArgs(must("VSOCK-LISTEN:9"))
		if err != nil {
			t.Fatal(err)
		}
		if args.family != vsockDefaultFamily || args.socktype != syscall.SOCK_STREAM || args.protocol != 0 {
			t.Fatalf("got %+v", args)
		}
	})
	t.Run("pf-inet", func(t *testing.T) {
		args, err := parseVsockSocketArgs(must("VSOCK-LISTEN:9,pf=inet"))
		if err != nil {
			t.Fatal(err)
		}
		if args.family != syscall.AF_INET {
			t.Fatalf("family=%d", args.family)
		}
	})
	t.Run("protocol-family", func(t *testing.T) {
		args, err := parseVsockSocketArgs(must("VSOCK-LISTEN:9,protocol-family=inet"))
		if err != nil {
			t.Fatal(err)
		}
		if args.family != syscall.AF_INET {
			t.Fatalf("family=%d", args.family)
		}
	})
	t.Run("pf-numeric", func(t *testing.T) {
		args, err := parseVsockSocketArgs(must("VSOCK-LISTEN:9,pf=40"))
		if err != nil {
			t.Fatal(err)
		}
		if args.family != 40 {
			t.Fatalf("family=%d", args.family)
		}
	})
	t.Run("pf-unknown", func(t *testing.T) {
		_, err := parseVsockSocketArgs(must("VSOCK-LISTEN:9,pf=vsock"))
		if err == nil || !strings.Contains(err.Error(), "unknown protocol family") {
			t.Fatalf("err=%v", err)
		}
	})
	t.Run("so-protocol", func(t *testing.T) {
		args, err := parseVsockSocketArgs(must("VSOCK-LISTEN:9,so-protocol=6"))
		if err != nil {
			t.Fatal(err)
		}
		if args.protocol != 6 {
			t.Fatalf("protocol=%d", args.protocol)
		}
	})
	t.Run("so-prototype-alias", func(t *testing.T) {
		args, err := parseVsockSocketArgs(must("VSOCK-LISTEN:9,so-prototype=6"))
		if err != nil {
			t.Fatal(err)
		}
		if args.protocol != 6 {
			t.Fatalf("protocol=%d", args.protocol)
		}
	})
	t.Run("protocol-alias", func(t *testing.T) {
		args, err := parseVsockSocketArgs(must("VSOCK-LISTEN:9,protocol=6"))
		if err != nil {
			t.Fatal(err)
		}
		if args.protocol != 6 {
			t.Fatalf("protocol=%d", args.protocol)
		}
	})
	t.Run("protocol-alias-last-wins", func(t *testing.T) {
		args, err := parseVsockSocketArgs(must("VSOCK-LISTEN:9,so-protocol=7,protocol=6"))
		if err != nil {
			t.Fatal(err)
		}
		if args.protocol != 6 {
			t.Fatalf("protocol=%d", args.protocol)
		}
	})
	t.Run("so-type-raw", func(t *testing.T) {
		args, err := parseVsockSocketArgs(must("VSOCK-LISTEN:9,so-type=3"))
		if err != nil {
			t.Fatal(err)
		}
		if args.socktype != 3 {
			t.Fatalf("socktype=%d", args.socktype)
		}
	})
	t.Run("type-raw", func(t *testing.T) {
		args, err := parseVsockSocketArgs(must("VSOCK-LISTEN:9,type=3"))
		if err != nil {
			t.Fatal(err)
		}
		if args.socktype != 3 {
			t.Fatalf("socktype=%d", args.socktype)
		}
	})
}
