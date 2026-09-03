//go:build linux

package filan

import (
	"fmt"
	"io"
	"os"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

func TestLibcDisplayCCPadsKernelCC(t *testing.T) {
	for _, n := range []int{0, 19, 23, 32} {
		in := make([]byte, n)
		for i := range in {
			in[i] = byte(i + 1)
		}
		got := libcDisplayCC(in)
		if len(got) != libcNCCS {
			t.Fatalf("n=%d len=%d want %d", n, len(got), libcNCCS)
		}
		limit := n
		if limit > libcNCCS {
			limit = libcNCCS
		}
		for i := 0; i < limit; i++ {
			if got[i] != in[i] {
				t.Fatalf("n=%d cc[%d]=%d want %d", n, i, got[i], in[i])
			}
		}
		for i := limit; i < libcNCCS; i++ {
			if got[i] != 0 {
				t.Fatalf("n=%d pad cc[%d]=%d want 0", n, i, got[i])
			}
		}
	}
}

func TestWriteFDLinuxTermiosMatchesLibc(t *testing.T) {
	master, slave, err := openTestPTY()
	if err != nil {
		t.Skip(err)
	}
	t.Cleanup(func() { _ = slave.Close(); _ = master.Close() })
	fd := int(slave.Fd())

	tios, err := unix.IoctlGetTermios(fd, unix.TCGETS)
	if err != nil {
		t.Fatal(err)
	}
	tios.Cflag |= uint32(unix.CIBAUD) & (uint32(unix.B38400) << 16)
	if err := unix.IoctlSetTermios(fd, unix.TCSETS, tios); err != nil {
		t.Fatal(err)
	}
	tios, err = unix.IoctlGetTermios(fd, unix.TCGETS)
	if err != nil {
		t.Fatal(err)
	}
	if tios.Cflag&uint32(unix.CIBAUD) == 0 {
		t.Fatal("test did not set CIBAUD")
	}

	got := dumpFD(t, fd)
	wantCflag := fmt.Sprintf("CFLAGS=0x%06x", tios.Cflag)
	if !strings.Contains(got, wantCflag) {
		t.Fatalf("missing %s in %q", wantCflag, got)
	}
	for i, ch := range libcDisplayCC(tios.Cc[:]) {
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

func TestFIONREADNegativeOffsetLinux(t *testing.T) {
	tmp, err := os.CreateTemp(t.TempDir(), "fionread-test-*")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = tmp.Close() })

	if _, err := tmp.Seek(100, io.SeekStart); err != nil {
		t.Fatal(err)
	}

	n, err := fionread(int(tmp.Fd()))
	if err != nil {
		t.Fatalf("fionread error: %v", err)
	}
	if n != -100 {
		t.Fatalf("fionread on empty file at offset 100: got %d, want -100", n)
	}
}
