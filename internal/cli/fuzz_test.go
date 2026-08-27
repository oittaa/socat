package cli

import (
	"reflect"
	"strings"
	"testing"

	"github.com/oittaa/socat/internal/parse"
)

func FuzzParseArgs(f *testing.F) {
	for _, seed := range []string{
		"-u\x00TCP:127.0.0.1:80\x00STDOUT",
		"-U\x00STDIN\x00TCP:127.0.0.1:80",
		"-d\x00-\x00-",
		"-d0\x00TCP4:127.0.0.1:1\x00STDOUT",
		"-hh",
		"-V",
		"--experimental\x00WS:127.0.0.1:80\x00STDOUT",
		"-b8192\x00-t0.5\x00STDIN\x00STDOUT",
		"-tbanana",
		"-T1e100",
		"-\x00-",
		"-,escape=27\x00STDOUT",
		"-!!-\x00TCP:127.0.0.1:80",
		"--\x00TCP:127.0.0.1:80\x00STDOUT",
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, joined string) {
		if len(joined) > 4096 {
			t.Skip()
		}
		args := strings.Split(joined, "\x00")
		if len(args) > 64 {
			args = args[:64]
		}
		first, err := ParseArgs(args)
		second, err2 := ParseArgs(args)
		if (err == nil) != (err2 == nil) {
			t.Fatalf("ParseArgs error is not deterministic: %v vs %v", err, err2)
		}
		if err != nil {
			return
		}
		if !reflect.DeepEqual(first, second) {
			t.Fatalf("ParseArgs is not deterministic: first=%+v second=%+v", first, second)
		}
	})
}

func FuzzValidateChannelOptions(f *testing.F) {
	for _, seed := range []string{
		"CREATE:file,perm=600",
		"CREATE:file,perm=xyz",
		"TCP:localhost:1,connect-timeout=soon",
		"TCP-LISTEN:1,fork,max-children=many",
		"UNIX:file,socktype=stream",
		"OPEN:file,ftruncate=-1",
		"TCP-LISTEN:1,setsockopt-listen=1:2",
		"TCP:localhost:1,setsockopt-bin=1:9:x01000000",
		"TLS:localhost:443,ciphers",
		"TCP4:127.0.0.1:80,reuseaddr",
		"STDIN!!STDOUT",
		"CREATE:file,totally-unknown=1",
		`EXEC:"echo hi",pty`,
		"WS:127.0.0.1:80,path=/echo",
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, input string) {
		if len(input) > 4096 {
			t.Skip()
		}
		ch, err := parse.ParseChannel(input)
		if err != nil {
			return
		}
		err1 := validateChannelOptions(ch)
		ch2, err2 := parse.ParseChannel(input)
		if err2 != nil {
			t.Fatalf("ParseChannel became failing: first=%v second=%v", err, err2)
		}
		err3 := validateChannelOptions(ch2)
		if (err1 == nil) != (err3 == nil) {
			t.Fatalf("validateChannelOptions is not deterministic: %v vs %v", err1, err3)
		}
		if err1 != nil && err3 != nil && err1.Error() != err3.Error() {
			t.Fatalf("validateChannelOptions error text changed: %q vs %q", err1, err3)
		}
	})
}
