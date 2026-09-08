package netopen

import (
	"testing"
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
