package parse

import "testing"

func BenchmarkParseSpecOptions(b *testing.B) {
	const input = "TCP6-LISTEN:443,so-reuseaddr,so-reuseport,ipv6-v6only=1,bind=[::],tcp-nodelay,so-keepalive,fork,max-children=64"
	b.ReportAllocs()
	for b.Loop() {
		if _, err := ParseSpec(input); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkOptionLookups(b *testing.B) {
	s, err := ParseSpec("TCP6-LISTEN:443,so-reuseaddr,so-reuseport,ipv6-v6only=1,bind=[::],tcp-nodelay,so-keepalive,fork")
	if err != nil {
		b.Fatal(err)
	}
	names := []string{"reuseaddr", "reuseport", "ipv6-v6only", "bind", "nodelay", "keepalive", "fork", "missing"}
	b.ReportAllocs()
	for b.Loop() {
		for _, name := range names {
			_, _ = s.OptionNamed(name)
		}
	}
}
