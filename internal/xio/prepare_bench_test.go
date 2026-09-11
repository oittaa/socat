package xio_test

import (
	"testing"

	"github.com/oittaa/socat/internal/parse"
	"github.com/oittaa/socat/internal/xio"
	_ "github.com/oittaa/socat/internal/xio/all"
)

func BenchmarkPrepareSpec(b *testing.B) {
	const input = "TCP6-LISTEN:443,so-reuseaddr,so-reuseport,ipv6-v6only=1,bind=[::],tcp-nodelay,so-keepalive,fork,max-children=64,retry=3,interval=250ms"
	spec, err := parse.ParseSpec(input)
	if err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	for b.Loop() {
		if _, err := xio.PrepareSpec(spec); err != nil {
			b.Fatal(err)
		}
	}
}
