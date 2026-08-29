package xio

import (
	"testing"

	"github.com/oittaa/socat/internal/parse"
)

func TestParseOwnerIoctlValue(t *testing.T) {
	got, err := parseOwnerIoctlValue(parse.Option{Name: "fiosetown"})
	if err != nil {
		t.Fatal(err)
	}
	if got != 1 {
		t.Fatalf("bare fiosetown parsed as %d want 1", got)
	}

	got, err = parseOwnerIoctlValue(parse.Option{Name: "siocspgrp", Value: "-1", Has: true})
	if err != nil {
		t.Fatal(err)
	}
	if got != -1 {
		t.Fatalf("siocspgrp=-1 parsed as %d", got)
	}

	got, err = parseOwnerIoctlValue(parse.Option{Name: "fiosetown", Value: "0x10", Has: true})
	if err != nil {
		t.Fatal(err)
	}
	if got != 16 {
		t.Fatalf("fiosetown=0x10 parsed as %d want 16", got)
	}

	if _, err := parseOwnerIoctlValue(parse.Option{Name: "fiosetown", Value: "no", Has: true}); err == nil {
		t.Fatal("fiosetown=no: expected invalid value")
	}
	if _, err := parseOwnerIoctlValue(parse.Option{Name: "siocspgrp", Value: "4294967296", Has: true}); err == nil {
		t.Fatal("siocspgrp overflow: expected invalid value")
	}
	if _, err := parseOwnerIoctlValue(parse.Option{Name: "fiosetown", Value: "", Has: true}); err == nil {
		t.Fatal("empty assigned fiosetown: expected invalid value")
	}
}

func TestIsOwnerIoctlOption(t *testing.T) {
	if !isOwnerIoctlOption("fiosetown") || !isOwnerIoctlOption("siocspgrp") {
		t.Fatal("canonical owner ioctl names must match")
	}
	if isOwnerIoctlOption("so-error") || isOwnerIoctlOption("ioctl") {
		t.Fatal("unrelated names must not match owner ioctl apply")
	}
}
