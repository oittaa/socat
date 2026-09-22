package xio_test

import (
	"strings"
	"testing"

	"github.com/oittaa/socat/internal/parse"
	"github.com/oittaa/socat/internal/xio"
	_ "github.com/oittaa/socat/internal/xio/all"
)

func TestPrepareBareRequiredOptionsFail(t *testing.T) {
	cases := []string{
		"SHELL:true,shell",
		"OPENSSL:127.0.0.1:9,cert",
		"TCP:127.0.0.1:9,bind",
		"TCP:127.0.0.1:9,sourceport",
		"EXEC:true,fdin",
		"EXEC:true,fdout",
		"FD:3,seek",
		"FD:3,seek-cur",
		"FD:3,seek-end",
		"UDP4:127.0.0.1:9,ip-multicast-ttl",
		"OPENSSL:127.0.0.1:9,commonname",
		"PROXY:proxy.test:target.test:80,proxy-authorization",
		"PTY,pty-interval",
	}
	for _, text := range cases {
		spec, err := parse.ParseSpec(text)
		if err != nil {
			t.Fatal(err)
		}
		_, err = xio.PrepareSpec(spec)
		if err == nil || !strings.Contains(err.Error(), "requires a value") {
			t.Fatalf("%s: %v", text, err)
		}
	}
}

func TestPrepareUnixBindTempnameOmissionIsNotTheStringOne(t *testing.T) {
	omitted, err := xio.PrepareSpec(mustParseSpec(t, "UNIX-CONNECT:/tmp/x,unix-bind-tempname"))
	if err != nil {
		t.Fatal(err)
	}
	name := omitted.Config.Network.UnixBindTempname
	if !name.Set || !name.Omitted || name.Value != "" {
		t.Fatalf("omitted=%+v", name)
	}

	explicit, err := xio.PrepareSpec(mustParseSpec(t, "UNIX-CONNECT:/tmp/x,unix-bind-tempname=1"))
	if err != nil {
		t.Fatal(err)
	}
	name = explicit.Config.Network.UnixBindTempname
	if name.Omitted || name.Value != "1" {
		t.Fatalf("explicit=%+v", name)
	}
}
