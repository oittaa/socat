package parse

import (
	"reflect"
	"strings"
	"testing"
)

func FuzzParseSpec(f *testing.F) {
	for _, seed := range []string{
		"-", "TCP4:127.0.0.1:80,reuseaddr", `EXEC:"echo a!!b",pty`,
		"UNIX-LISTEN:/tmp/example.sock,unlink-early", "TCP6:[::1]:443",
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, input string) {
		if len(input) > 4096 {
			t.Skip()
		}
		first, err := ParseSpec(input)
		second, err2 := ParseSpec(input)
		if (err == nil) != (err2 == nil) || (err == nil && !reflect.DeepEqual(first, second)) {
			t.Fatalf("ParseSpec is not deterministic: first=%+v/%v second=%+v/%v", first, err, second, err2)
		}
		if err == nil && first.Raw != strings.TrimSpace(input) {
			t.Fatalf("Raw=%q want %q", first.Raw, strings.TrimSpace(input))
		}
	})
}

func FuzzParseChannel(f *testing.F) {
	for _, seed := range []string{
		"stdin!!stdout", "OPEN:file,rdonly", `EXEC:"printf !!"`, "2", "/tmp/file",
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, input string) {
		if len(input) > 4096 {
			t.Skip()
		}
		channel, err := ParseChannel(input)
		if err != nil {
			return
		}
		if (channel.Single == nil) == (channel.Dual == nil) {
			t.Fatalf("channel must contain exactly one representation: %+v", channel)
		}
		if channel.Raw != strings.TrimSpace(input) {
			t.Fatalf("Raw=%q want %q", channel.Raw, strings.TrimSpace(input))
		}
	})
}
