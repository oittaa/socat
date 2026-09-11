package addrconfig_test

import (
	"bytes"
	"testing"

	"github.com/oittaa/socat/internal/addrconfig"
	"github.com/oittaa/socat/internal/parse"
)

func TestDecodeIoctlBinMatchesRuntimeDalan(t *testing.T) {
	for _, value := range []string{
		`i1 2`,
		`"a\n"'\t'x0102x0304`,
		`b1`,
		`l-1`,
	} {
		t.Run(value, func(t *testing.T) {
			spec := parse.Spec{
				Type: "FD",
				Options: []parse.Option{{
					Name:  "ioctl-bin",
					Has:   true,
					Value: "7:" + value,
				}},
			}
			config, err := addrconfig.Decode(spec, addrconfig.Facts{Type: "FD"})
			if err != nil {
				t.Fatal(err)
			}
			if len(config.File.Actions) != 1 {
				t.Fatalf("actions=%+v", config.File.Actions)
			}
			want, _, err := addrconfig.ParseDalan(value, 'i')
			if err != nil {
				t.Fatal(err)
			}
			if got := config.File.Actions[0].Bytes; !bytes.Equal(got, want) {
				t.Fatalf("ioctl-bin bytes=%x want %x", got, want)
			}
		})
	}
}

func TestDecodeIoctlBinRejectsRuntimeDalanErrors(t *testing.T) {
	for _, value := range []string{"x0", `'ab'`, `"unterminated`, "X0102"} {
		t.Run(value, func(t *testing.T) {
			spec := parse.Spec{
				Type: "FD",
				Options: []parse.Option{{
					Name:  "ioctl-bin",
					Has:   true,
					Value: "7:" + value,
				}},
			}
			if _, err := addrconfig.Decode(spec, addrconfig.Facts{Type: "FD"}); err == nil {
				t.Fatal("Decode succeeded")
			}
			if _, _, err := addrconfig.ParseDalan(value, 'i'); err == nil {
				t.Fatal("ParseDalan succeeded")
			}
		})
	}
}
