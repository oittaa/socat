package quicopen

import (
	"testing"

	"github.com/oittaa/socat/internal/parse"
)

func FuzzQUICTarget(f *testing.F) {
	for _, seed := range []string{
		"QUIC:example.com:4433",
		"QUIC-LISTEN:4433",
		"QUIC-LISTEN",
		"QUIC:onlyhost",
		"QUIC:h:1,alpn=foo",
		"QUIC:[::1]:4433",
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, input string) {
		if len(input) > 4096 {
			t.Skip("input exceeds 4096 bytes")
		}
		s, err := parse.ParseSpec(input)
		if err != nil {
			return
		}
		_, _, _ = quicTarget(s, false)
		_, _, _ = quicTarget(s, true)
	})
}
