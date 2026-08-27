package xio

import (
	"strings"
	"testing"

	"github.com/oittaa/socat/internal/parse"
)

func TestParseClassicCIntOverflowAndHex(t *testing.T) {
	n, err := parseClassicCInt("0x541B")
	if err != nil || n != 0x541B {
		t.Fatalf("0x541B: n=%d err=%v", n, err)
	}
	n, err = parseClassicCInt("-1")
	if err != nil || n != -1 {
		t.Fatalf("-1: n=%d err=%v", n, err)
	}
	n, err = parseClassicCInt("0x80000000")
	if err != nil || int32(n) != int32(-2147483648) {
		t.Fatalf("0x80000000: n=%d err=%v", n, err)
	}
	if _, err := parseClassicCInt("4294967296"); err == nil {
		t.Fatal("2^32 must overflow")
	}
	if _, err := parseClassicCInt("0x100000000"); err == nil {
		t.Fatal("0x100000000 must overflow")
	}
	if _, err := parseClassicCInt(""); err == nil {
		t.Fatal("empty must fail")
	}
	if _, err := parseClassicCInt("10junk"); err == nil {
		t.Fatal("trailing junk must fail")
	}
}

func TestParseGenericIoctlTypes(t *testing.T) {
	voidSpec, err := parse.ParseSpec("FD:3,ioctl-void=0x541B")
	if err != nil {
		t.Fatal(err)
	}
	got, err := parseGenericIoctl(voidSpec.Options[0])
	if err != nil || got.kind != ioctlKindVoid || got.req != 0x541B {
		t.Fatalf("void: %+v err=%v", got, err)
	}

	alias, err := parse.ParseSpec("FD:3,ioctl=21531")
	if err != nil {
		t.Fatal(err)
	}
	got, err = parseGenericIoctl(alias.Options[0])
	if err != nil || got.kind != ioctlKindVoid || got.req != 21531 {
		t.Fatalf("alias: %+v err=%v", got, err)
	}

	intp, err := parse.ParseSpec("FD:3,ioctl-intp=1:2")
	if err != nil {
		t.Fatal(err)
	}
	got, err = parseGenericIoctl(intp.Options[0])
	if err != nil || got.kind != ioctlKindIntp || got.req != 1 || got.intVal != 2 {
		t.Fatalf("intp: %+v err=%v", got, err)
	}

	bin, err := parse.ParseSpec("FD:3,ioctl-bin=1:x01000000")
	if err != nil {
		t.Fatal(err)
	}
	got, err = parseGenericIoctl(bin.Options[0])
	if err != nil || got.kind != ioctlKindBin || len(got.bin) != 4 {
		t.Fatalf("bin: %+v err=%v", got, err)
	}

	str, err := parse.ParseSpec("FD:3,ioctl-string=1:hello:world")
	if err != nil {
		t.Fatal(err)
	}
	got, err = parseGenericIoctl(str.Options[0])
	if err != nil || got.str != "hello:world" {
		t.Fatalf("string rest=%q err=%v", got.str, err)
	}

	empty, err := parse.ParseSpec("FD:3,ioctl-string=1:")
	if err != nil {
		t.Fatal(err)
	}
	got, err = parseGenericIoctl(empty.Options[0])
	if err != nil || got.str != "" {
		t.Fatalf("empty string rest=%q err=%v", got.str, err)
	}

	notDalan, err := parse.ParseSpec("FD:3,ioctl-string=1:512junk")
	if err != nil {
		t.Fatal(err)
	}
	got, err = parseGenericIoctl(notDalan.Options[0])
	if err != nil || got.str != "512junk" {
		t.Fatalf("ioctl-string follows C (plain string), not dalan: rest=%q err=%v", got.str, err)
	}
}

func TestParseGenericIoctlRejectsMalformed(t *testing.T) {
	tests := []struct {
		raw  string
		want string
	}{
		{raw: "FD:3,ioctl-void", want: "requires a value"},
		{raw: "FD:3,ioctl-void=4294967296", want: "invalid ioctl-void"},
		{raw: "FD:3,ioctl-int=1", want: "invalid ioctl-int"},
		{raw: "FD:3,ioctl-int=1:4294967296", want: "invalid ioctl-int"},
		{raw: "FD:3,ioctl-intp=4294967296:0", want: "invalid ioctl-intp"},
		{raw: "FD:3,ioctl-intp=1:nope", want: "invalid ioctl-intp"},
		{raw: "FD:3,ioctl-bin=1:not-a-dalan", want: "invalid ioctl-bin"},
		{raw: "FD:3,ioctl-bin=1:", want: "empty dalan"},
		{raw: "FD:3,ioctl-bin=1:512junk", want: "invalid ioctl-bin"},
		{raw: "FD:3,ioctl-string=1", want: "invalid ioctl-string"},
	}
	for _, tc := range tests {
		s := mustSpec(t, tc.raw)
		if err := ValidateGenericIoctl(s.Options[0]); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: err=%v want %q", tc.raw, err, tc.want)
		}
	}
}

func TestHasFDLifecycleOptionsIoctl(t *testing.T) {
	if !hasFDLifecycleOptions(mustSpec(t, "FD:3,ioctl-void=1")) {
		t.Fatal("ioctl-void must trigger ApplyFDOptions")
	}
	if !hasFDLifecycleOptions(mustSpec(t, "TCP:localhost:1,ioctl=1")) {
		t.Fatal("ioctl alias must trigger ApplyFDOptions")
	}
	if !hasFDLifecycleOptions(mustSpec(t, "OPEN:file,ioctl-string=1:x")) {
		t.Fatal("ioctl-string must trigger ApplyFDOptions")
	}
}

func TestGenericIoctlOptionNames(t *testing.T) {
	for _, name := range []string{"ioctl", "ioctl-void", "ioctl-int", "ioctl-intp", "ioctl-bin", "ioctl-string"} {
		if !GenericIoctlOption(name) {
			t.Errorf("%s: GenericIoctlOption=false", name)
		}
	}
	if GenericIoctlOption("setsockopt") {
		t.Fatal("setsockopt is not a generic ioctl option")
	}
}
