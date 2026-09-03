package parse

import (
	"reflect"
	"strings"
	"testing"
)

func FuzzParseSpec(f *testing.F) {
	for _, seed := range []string{
		"-", "-,escape=27", "TCP4:127.0.0.1:80,reuseaddr", `EXEC:"echo a!!b",pty`,
		"UNIX-LISTEN:/tmp/example.sock,unlink-early", "TCP6:[::1]:443",
		`CREATE:C:\temp\file`, `OPEN:C:\temp\file,rdonly`, `\\server\share\file`,
		"CREATE:C:/temp/file", "GOPEN:/tmp/a,b,creat", "TEXT:hello\\tworld",
		"TCP-LISTEN:8080,reuseaddr,fork,bind=127.0.0.1",
		"TLS:example.com:443,verify=0,commonname=example.com",
		"WS:example.com:80/echo/v1", "QUIC:[::1]:4433,alpn=socat",
		"", "::::", ",,,,", strings.Repeat("A,", 200),
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, input string) {
		if len(input) > 4096 {
			t.Skip("input exceeds 4096 bytes")
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
		"-!!-", "STDIN!!STDOUT", `EXEC:"echo a!!b"!!STDOUT`,
		`CREATE:C:\out.txt`, "TCP6:[::1]:443!!STDOUT",
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, input string) {
		if len(input) > 4096 {
			t.Skip("input exceeds 4096 bytes")
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
