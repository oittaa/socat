//go:build linux || darwin

package xio

import (
	"bytes"
	"os"
	"strconv"
	"strings"
	"testing"

	"github.com/oittaa/socat/internal/logx"
	"github.com/oittaa/socat/internal/relay"
)

func TestDumpSideOmitsDuplicateWriteFD(t *testing.T) {
	f, err := os.CreateTemp(t.TempDir(), "rw")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = f.Close() })
	stream := FileStream(f)
	rfd := relay.StreamReadFD(stream)
	wfd := relay.StreamWriteFD(stream)
	if rfd < 0 || rfd != wfd {
		t.Fatalf("read=%d write=%d", rfd, wfd)
	}
	var dump bytes.Buffer
	g := &Global{DumpFDs: true, DumpFDOut: &dump, Log: logx.New()}
	g.dumpSessionFDs(stream, nil)
	var fds []int
	for _, line := range strings.Split(dump.String(), "\n") {
		colon := strings.Index(line, ":")
		if colon <= 0 {
			continue
		}
		n, err := strconv.Atoi(strings.TrimSpace(line[:colon]))
		if err != nil {
			continue
		}
		fds = append(fds, n)
	}
	if len(fds) != 1 || fds[0] != rfd {
		t.Fatalf("fds=%v dump=%q", fds, dump.String())
	}
}
