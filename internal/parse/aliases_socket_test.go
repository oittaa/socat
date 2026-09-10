package parse

import "testing"

func TestSocketAliasesPreserveSpelling(t *testing.T) {
	for spelling, canonical := range map[string]string{
		"tcp-nodelay": "nodelay", "tcp-keepalive": "keepalive", "linger": "linger",
	} {
		spec, err := ParseSpec("TCP4:127.0.0.1:1," + spelling + "=1")
		if err != nil {
			t.Fatal(err)
		}
		option := spec.Options[0]
		if option.Name != canonical || option.OriginalSpelling() != spelling || !option.Has || option.Value != "1" {
			t.Errorf("%s: parsed %+v", spelling, option)
		}
	}
}
