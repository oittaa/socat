//go:build darwin

package filan

import (
	"regexp"
	"strconv"
	"strings"
	"testing"
	"unsafe"

	"golang.org/x/sys/unix"
)

func TestWriteFDUnnamedUnixReportsKernelLen(t *testing.T) {
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = unix.Close(fds[0])
		_ = unix.Close(fds[1])
	})

	var rsa unix.RawSockaddrAny
	l := uint32(unsafe.Sizeof(rsa))                                                                                                // #nosec G115 -- socklen_t
	_, _, errno := unix.Syscall(unix.SYS_GETSOCKNAME, uintptr(fds[0]), uintptr(unsafe.Pointer(&rsa)), uintptr(unsafe.Pointer(&l))) // #nosec G103 -- getsockname writes sockaddr
	if errno != 0 {
		t.Fatal(errno)
	}
	want := int(rsa.Addr.Len)
	if want == 0 {
		t.Fatal("kernel sa_len is 0")
	}

	got := dumpFD(t, fds[0])
	if !strings.Contains(got, `"<anon>"`) {
		t.Fatalf("missing <anon> display: %q", got)
	}
	anonDisplayLen := 2 + len("<anon>") + 1
	m := regexp.MustCompile(`LEN=(\d+) AF=` + strconv.Itoa(unix.AF_UNIX)).FindStringSubmatch(got)
	if m == nil {
		t.Fatalf("missing LEN= for AF_UNIX: %q", got)
	}
	n, err := strconv.Atoi(m[1])
	if err != nil {
		t.Fatal(err)
	}
	if n == anonDisplayLen {
		t.Fatalf("LEN used <anon> display width %d: %q", n, got)
	}
	if n != want {
		t.Fatalf("LEN=%d want kernel sa_len %d (%q)", n, want, got)
	}
}
