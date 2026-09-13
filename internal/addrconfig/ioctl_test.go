package addrconfig_test

import (
	"bytes"
	"testing"

	"github.com/oittaa/socat/internal/addrconfig"
	"github.com/oittaa/socat/internal/parse"
)

func TestDecodeIoctlBinBytes(t *testing.T) {
	for _, tc := range []struct {
		value string
		want  []byte
	}{
		{`x01020304`, []byte{1, 2, 3, 4}},
		{`"a\n"'\t'x0102x0304`, []byte{'a', '\n', '\t', 1, 2, 3, 4}},
	} {
		t.Run(tc.value, func(t *testing.T) {
			spec := parse.Spec{
				Type: "FD",
				Options: []parse.Option{{
					Name:  "ioctl-bin",
					Has:   true,
					Value: "7:" + tc.value,
				}},
			}
			config, err := addrconfig.Decode(spec, addrconfig.Facts{Type: "FD"})
			if err != nil {
				t.Fatal(err)
			}
			if len(config.File.Actions) != 1 {
				t.Fatalf("actions=%+v", config.File.Actions)
			}

			if got := config.File.Actions[0].Bytes; !bytes.Equal(got, tc.want) {
				t.Fatalf("ioctl-bin bytes=%x want %x", got, tc.want)
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
		})
	}
}
