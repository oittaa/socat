package netopen

import (
	"runtime"
	"testing"

	"github.com/oittaa/socat/internal/parse"
)

func TestClassicUnixSockaddrLenMatchesXiosetunix(t *testing.T) {
	// Linux sizeof(sockaddr_un)=110, sizeof(sun_path)=108 (x/sys SizeofSockaddrUnix).
	const sizeofUn, sunPath = 110, 108
	pathlen := len("hello")
	if got := classicUnixSockaddrLen(pathlen, sunPath, sizeofUn, false, true); got != 2+pathlen {
		t.Fatalf("pathname tight=%d want %d", got, 2+pathlen)
	}
	if got := classicUnixSockaddrLen(pathlen, sunPath, sizeofUn, false, false); got != sizeofUn {
		t.Fatalf("pathname untight=%d want %d", got, sizeofUn)
	}
	if got := classicUnixSockaddrLen(pathlen, sunPath, sizeofUn, true, true); got != 2+pathlen+1 {
		t.Fatalf("abstract tight=%d want %d", got, 2+pathlen+1)
	}
	if got := classicUnixSockaddrLen(pathlen, sunPath, sizeofUn, true, false); got != sizeofUn {
		t.Fatalf("abstract untight=%d want %d", got, sizeofUn)
	}
}

func TestUnixTightSocklenDefaultByGOOS(t *testing.T) {
	// compat.h UNIX_TIGHTSOCKLEN: false on FreeBSD/OpenBSD, true elsewhere.
	if !unixTightSocklenDefault("linux") || !unixTightSocklenDefault("darwin") || !unixTightSocklenDefault("windows") {
		t.Fatal("linux/darwin/windows default must be tight")
	}
	if unixTightSocklenDefault("freebsd") || unixTightSocklenDefault("openbsd") {
		t.Fatal("freebsd/openbsd default must be sizeof(sockaddr_un)")
	}
}

func TestUnixTightSocklenDefaultAndValues(t *testing.T) {
	omitted, err := parse.ParseSpec("UNIX-LISTEN:sock")
	if err != nil {
		t.Fatal(err)
	}
	if unixTightSocklen(omitted) != unixTightSocklenDefault(runtime.GOOS) {
		t.Fatalf("omitted=%v want %v", unixTightSocklen(omitted), unixTightSocklenDefault(runtime.GOOS))
	}
	on, err := parse.ParseSpec("UNIX-LISTEN:sock,unix-tightsocklen=1")
	if err != nil {
		t.Fatal(err)
	}
	if !unixTightSocklen(on) {
		t.Fatal("=1 must stay tight")
	}
	alias, err := parse.ParseSpec("UNIX-LISTEN:sock,tightsocklen")
	if err != nil {
		t.Fatal(err)
	}
	if !unixTightSocklen(alias) {
		t.Fatal("bare tightsocklen must stay tight")
	}
	off, err := parse.ParseSpec("UNIX-LISTEN:sock,tightsocklen=0")
	if err != nil {
		t.Fatal(err)
	}
	if unixTightSocklen(off) {
		t.Fatal("=0 must use sizeof(sockaddr_un)")
	}
}
