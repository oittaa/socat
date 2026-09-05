//go:build linux || darwin

package relay

import (
	"os"
	"testing"

	"golang.org/x/sys/unix"
)

func TestInheritedSocketSemantics(t *testing.T) {
	for _, typ := range []int{unix.SOCK_STREAM, unix.SOCK_DGRAM} {
		fds, err := unix.Socketpair(unix.AF_UNIX, typ, 0)
		if err != nil {
			t.Fatal(err)
		}
		a, b := os.NewFile(uintptr(fds[0]), "stdio"), os.NewFile(uintptr(fds[1]), "peer")
		kind := MessageIO
		if typ == unix.SOCK_STREAM {
			kind = ByteStreamIO
		}
		s := FDStream{R: a, W: a}
		gotRead, gotWrite := StreamReadSemantics(s), StreamWriteSemantics(s)
		_ = a.Close()
		_ = b.Close()
		if gotRead != kind || gotWrite != kind {
			t.Fatalf("socket type %d read/write = %v/%v", typ, gotRead, gotWrite)
		}
	}
}
