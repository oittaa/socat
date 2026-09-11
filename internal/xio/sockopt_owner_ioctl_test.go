package xio

import (
	"testing"

	"github.com/oittaa/socat/internal/addrconfig"
	"github.com/oittaa/socat/internal/parse"
)

func TestOwnerIoctlNamesDecode(t *testing.T) {
	s, err := parse.ParseSpec("TCP:127.0.0.1:9,fiosetown=1,siocspgrp=2")
	if err != nil {
		t.Fatal(err)
	}
	config, err := addrconfig.Decode(s, addrconfig.Facts{Type: "TCP"})
	if err != nil {
		t.Fatal(err)
	}
	var sawFIOS, sawPGRP bool
	for _, action := range config.Network.Actions {
		if action.Kind != addrconfig.SocketActionNamed {
			continue
		}
		switch action.Named {
		case addrconfig.NamedSocketFIOSETOWN:
			sawFIOS = action.Number == 1
		case addrconfig.NamedSocketSIOCSPGRP:
			sawPGRP = action.Number == 2
		}
	}
	if !sawFIOS || !sawPGRP {
		t.Fatalf("owner ioctl actions missing: %+v", config.Network.Actions)
	}
}

func TestUnrelatedNamesAreNotOwnerIoctls(t *testing.T) {
	s, err := parse.ParseSpec("TCP:127.0.0.1:9,so-debug")
	if err != nil {
		t.Fatal(err)
	}
	config, err := addrconfig.Decode(s, addrconfig.Facts{Type: "TCP"})
	if err != nil {
		t.Fatal(err)
	}
	for _, action := range config.Network.Actions {
		if action.Kind == addrconfig.SocketActionNamed &&
			(action.Named == addrconfig.NamedSocketFIOSETOWN || action.Named == addrconfig.NamedSocketSIOCSPGRP) {
			t.Fatalf("so-debug decoded as owner ioctl: %+v", action)
		}
	}
}
