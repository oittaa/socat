package xio

import (
	"testing"
)

func TestIsOwnerIoctlOption(t *testing.T) {
	if !isOwnerIoctlOption("fiosetown") || !isOwnerIoctlOption("siocspgrp") {
		t.Fatal("canonical owner ioctl names must match")
	}
	if isOwnerIoctlOption("so-error") || isOwnerIoctlOption("ioctl") {
		t.Fatal("unrelated names must not match owner ioctl apply")
	}
}
