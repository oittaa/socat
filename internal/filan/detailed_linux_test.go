//go:build linux

package filan

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"unsafe"

	"golang.org/x/sys/unix"
)

func TestWriteFDLinuxTermiosMatchesLibc(t *testing.T) {
	master, slave, err := openTestPTY()
	if err != nil {
		t.Skip(err)
	}
	t.Cleanup(func() { _ = slave.Close(); _ = master.Close() })
	fd := int(slave.Fd())

	var tios libcTermios
	_, _, errno := unix.Syscall(unix.SYS_IOCTL, uintptr(fd), uintptr(unix.TCGETS), uintptr(unsafe.Pointer(&tios))) // #nosec G103 -- TCGETS reads libc termios
	if errno != 0 {
		t.Fatal(errno)
	}
	tios.Cflag |= uint32(unix.CIBAUD) & (uint32(unix.B38400) << 16)
	_, _, errno = unix.Syscall(unix.SYS_IOCTL, uintptr(fd), uintptr(unix.TCSETS), uintptr(unsafe.Pointer(&tios))) // #nosec G103 -- TCSETS writes libc termios
	if errno != 0 {
		t.Fatal(errno)
	}
	_, _, errno = unix.Syscall(unix.SYS_IOCTL, uintptr(fd), uintptr(unix.TCGETS), uintptr(unsafe.Pointer(&tios))) // #nosec G103 -- re-read after TCSETS
	if errno != 0 {
		t.Fatal(errno)
	}

	got := dumpFD(t, fd)
	wantCflag := fmt.Sprintf("CFLAGS=0x%06x", tios.Cflag)
	if !strings.Contains(got, wantCflag) {
		t.Fatalf("missing %s in %q", wantCflag, got)
	}
	k, err := unix.IoctlGetTermios(fd, unix.TCGETS)
	if err != nil {
		t.Fatal(err)
	}
	if uint32(k.Cflag) != tios.Cflag {
		t.Fatalf("TCGETS Cflag=%#x libcTermios=%#x", k.Cflag, tios.Cflag)
	}
	if tios.Cflag&uint32(unix.CIBAUD) == 0 {
		t.Fatal("test did not set CIBAUD")
	}
	for i, ch := range tios.Cc {
		want := fmt.Sprintf("cc[%d]=%s", i, ccString(ch, false))
		if !strings.Contains(got, want) {
			t.Fatalf("missing %s in %q", want, got)
		}
	}
	if strings.Contains(got, "cc[32]=") {
		t.Fatalf("unexpected cc[32] in %q", got)
	}
	if last := strings.LastIndex(got, "cc["); last >= 0 {
		rest := got[last+len("cc["):]
		n, err := strconv.Atoi(strings.SplitN(rest, "]", 2)[0])
		if err != nil || n != libcNCCS-1 {
			t.Fatalf("last cc index=%q want %d (%q)", rest, libcNCCS-1, got)
		}
	}
}

func TestWriteFDConnectedTCPLinuxSockopts(t *testing.T) {
	client, server := connectedTCP(t)
	if _, err := client.Write([]byte("hello")); err != nil {
		t.Fatal(err)
	}
	fd := connFD(t, server)
	waitPOLLIN(t, fd)
	got := dumpFD(t, fd)
	for _, want := range []string{
		"ATTACH_FILTER=\"\"",
		"IP_ROUTER_ALERT=",
		"IP_PKTOPTIONS=\"\"",
		"IP_MTU_DISCOVER=",
		"IP_RECVERR=",
		"IP_TRANSPARENT=",
		"IP_MTU=",
		"IP_FREEBIND=",
		"TCP_INFO={",
		"TCPI_STATE={",
		"TCPI_OPTIONS={",
		"TCPI_SND_WSCALE={",
		"TCPI_RCV_WSCALE={",
		"recvmsg=1,",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("missing %s in %q", want, got)
		}
	}
	state := regexp.MustCompile(`TCPI_STATE=\{(\d+)\}`).FindStringSubmatch(got)
	if state == nil {
		t.Fatalf("TCPI_STATE value missing: %q", got)
	}
	n, err := strconv.Atoi(state[1])
	if err != nil || n == 0 {
		t.Fatalf("TCPI_STATE=%q want established non-zero", state[1])
	}
}
