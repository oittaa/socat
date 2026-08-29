//go:build darwin

package netopen

import (
	"testing"

	"golang.org/x/sys/unix"
)

func TestUnixRawSockaddrSetsSunLenInBothModes(t *testing.T) {
	sizeofUn := unix.SizeofSockaddrUnix
	sa, n, err := unixRawSockaddr("hello", false)
	if err != nil {
		t.Fatal(err)
	}
	if n != sizeofUn {
		t.Fatalf("untight socklen=%d want sizeof=%d", n, sizeofUn)
	}
	if int(sa.Len) != n {
		t.Fatalf("untight sun_len=%d want sizeof=%d (socket_un_init)", sa.Len, n)
	}
	sa, n, err = unixRawSockaddr("hello", true)
	if err != nil {
		t.Fatal(err)
	}
	want := classicUnixSockaddrLen(len("hello"), len(sa.Path), sizeofUn, false, true)
	if n != want {
		t.Fatalf("tight socklen=%d want %d", n, want)
	}
	if int(sa.Len) != n {
		t.Fatalf("tight sun_len=%d want calculated %d", sa.Len, n)
	}
}
