package addrconfig

import (
	"testing"

	"github.com/oittaa/socat/internal/parse"
)

const benchmarkTCP = "TCP6-LISTEN:443,so-reuseaddr,so-reuseport,ipv6-v6only=1,bind=[::],tcp-nodelay,so-keepalive,fork,max-children=64,retry=3,interval=250ms,handshake-timeout=2"

func BenchmarkDecodeAddress(b *testing.B) {
	spec, err := parse.ParseSpec(benchmarkTCP)
	if err != nil {
		b.Fatal(err)
	}
	facts := Facts{Type: "TCP6-LISTEN", Group: "TCP", Caps: []string{"socket"}}
	b.ReportAllocs()
	for b.Loop() {
		if _, err := Decode(spec, facts); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkPreparedRetryReuse(b *testing.B) {
	spec, err := parse.ParseSpec(benchmarkTCP)
	if err != nil {
		b.Fatal(err)
	}
	prepared, err := Decode(spec, Facts{Type: "TCP6-LISTEN", Group: "TCP", Caps: []string{"socket"}})
	if err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	for b.Loop() {
		_ = prepared.Common.Retry.Policy()
	}
}
