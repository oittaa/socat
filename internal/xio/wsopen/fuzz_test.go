package wsopen

import (
	"testing"

	"github.com/oittaa/socat/internal/parse"
)

func FuzzWSTarget(f *testing.F) {
	for _, seed := range []string{
		"WS:example.com:80/echo/v1",
		"WS:127.0.0.1:9,path=/foo",
		"WS-LISTEN:8080/echo",
		"WSS:example.com:443",
		"WS:127.0.0.1:80",
		"WS:example.com:80:echo:v1",
		"WS-LISTEN",
		"WS:onlyhost",
		"WS:[::1]:80/path",
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
		_, _, _, _ = wsTarget(s, false)
		_, _, _, _ = wsTarget(s, true)
	})
}
