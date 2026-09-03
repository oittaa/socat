//go:build linux || darwin

package xio_test

import (
	"bytes"
	"context"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/oittaa/socat/internal/logx"
	"github.com/oittaa/socat/internal/xio"
	_ "github.com/oittaa/socat/internal/xio/all"
)

func reportedDumpFDs(text string) []int {
	var fds []int
	for _, line := range strings.Split(text, "\n") {
		if !strings.Contains(line, ":") {
			continue
		}
		colon := strings.Index(line, ":")
		n, err := strconv.Atoi(strings.TrimSpace(line[:colon]))
		if err != nil {
			continue
		}
		fds = append(fds, n)
	}
	return fds
}

type dumpBuf struct {
	mu     sync.Mutex
	b      bytes.Buffer
	notify chan struct{}
}

func (d *dumpBuf) Write(p []byte) (int, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	n, err := d.b.Write(p)
	if d.notify != nil {
		select {
		case d.notify <- struct{}{}:
		default:
		}
	}
	return n, err
}

func (d *dumpBuf) String() string {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.b.String()
}

func TestDumpFDsPrintsChannelDescriptorsInOrder(t *testing.T) {
	dir := t.TempDir()
	inPath := filepath.Join(dir, "in")
	outPath := filepath.Join(dir, "out")
	if err := os.WriteFile(inPath, []byte("hi\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(outPath, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	sp0, sp1, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = sp0.Close(); _ = sp1.Close() })
	internal := []int{int(sp0.Fd()), int(sp1.Fd())}

	var dump bytes.Buffer
	log := logx.New()
	log.SetOutput(&bytes.Buffer{})
	g := &xio.Global{
		Log:         log,
		BlockSize:   8192,
		Linger:      10 * time.Millisecond,
		LeftToRight: true,
		DumpFDs:     true,
		DumpFDOut:   &dump,
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := xio.Run(ctx, mustParse(t, "OPEN:"+inPath+",rdonly"), mustParse(t, "OPEN:"+outPath+",wronly"), g); err != nil {
		t.Fatal(err)
	}
	text := dump.String()
	if strings.Count(text, "  FD  type") != 1 {
		t.Fatalf("want one header, got %q", text)
	}
	header := strings.SplitN(text, "\n", 2)[0]
	if !strings.Contains(header, "\tblksize\tblocks\t") {
		t.Fatalf("header missing blksize/blocks columns: %q", header)
	}
	if strings.Contains(header, "typedevice") {
		t.Fatalf("header lacks tab separators: %q", header)
	}
	fds := reportedDumpFDs(text)
	if len(fds) != 2 {
		t.Fatalf("fds=%v dump=%q", fds, text)
	}
	if fds[0] == fds[1] {
		t.Fatalf("expected distinct left then right FDs: %v", fds)
	}
	for _, fd := range internal {
		for _, got := range fds {
			if got == fd {
				t.Fatalf("internal pipe fd %d appeared in dump %v", fd, fds)
			}
		}
	}
}

func TestDumpFDsOncePerForkSession(t *testing.T) {
	dump := dumpBuf{notify: make(chan struct{}, 10)}
	log := logx.New()
	log.SetOutput(&bytes.Buffer{})
	g := &xio.Global{
		Log:       log,
		BlockSize: 8192,
		Linger:    50 * time.Millisecond,
		DumpFDs:   true,
		DumpFDOut: &dump,
	}
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	lo := startForkListenPIPE(t, ctx, g, "TCP4-LISTEN:0,fork,reuseaddr")
	port := listenerPort(t, lo)
	addr := net.JoinHostPort("127.0.0.1", strconv.Itoa(port))
	for range 2 {
		c := openClient(t, ctx, g, "TCP4:"+addr)
		mustWrite(t, c.Stream, []byte("ab"))
		_ = readFull(t, c.Stream, 2)
		_ = c.Close()
	}
	timer := time.NewTimer(2 * time.Second)
	defer timer.Stop()
	for {
		count := strings.Count(dump.String(), "  FD  type")
		if count == 2 {
			select {
			case <-dump.notify:
				if n := strings.Count(dump.String(), "  FD  type"); n != 2 {
					t.Fatalf("want exactly two dumps, got %d: %q", n, dump.String())
				}
			case <-time.After(50 * time.Millisecond):
			}
			return
		}
		if count > 2 {
			t.Fatalf("want exactly two dumps, got %d: %q", count, dump.String())
		}
		select {
		case <-dump.notify:
		case <-timer.C:
			t.Fatalf("want two dumps, got %d: %q", count, dump.String())
		}
	}
}

func TestDumpFDsOmitsSniffFiles(t *testing.T) {
	dir := t.TempDir()
	inPath := filepath.Join(dir, "in")
	outPath := filepath.Join(dir, "out")
	sniff := filepath.Join(dir, "sniff")
	if err := os.WriteFile(inPath, []byte("hi\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(outPath, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	var dump bytes.Buffer
	g := &xio.Global{
		Log:         logx.New(),
		BlockSize:   8192,
		Linger:      10 * time.Millisecond,
		LeftToRight: true,
		DumpFDs:     true,
		DumpFDOut:   &dump,
		RawLeftPath: sniff,
		Progname:    "socat",
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := xio.Run(ctx, mustParse(t, "OPEN:"+inPath+",rdonly"), mustParse(t, "OPEN:"+outPath+",wronly"), g); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(dump.String(), sniff) {
		t.Fatalf("sniff path leaked into dump: %q", dump.String())
	}
	if _, err := os.Stat(sniff); err != nil {
		t.Fatalf("sniff file should still be created: %v", err)
	}
}

func TestNoforkSkipsDumpAndMixedLog(t *testing.T) {
	rec := installMixSyslog(t)
	dir := t.TempDir()
	inPath := filepath.Join(dir, "in")
	if err := os.WriteFile(inPath, []byte("hi\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	var dump bytes.Buffer
	var stderr bytes.Buffer
	log := logx.New()
	log.SetOutput(&stderr)
	log.SetLevel(logx.Info)
	g := &xio.Global{
		Log:         log,
		BlockSize:   8192,
		Linger:      10 * time.Millisecond,
		LeftToRight: true,
		DumpFDs:     true,
		DumpFDOut:   &dump,
		LogMixed:    true,
		LogFacility: "daemon",
		Progname:    "socat",
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := xio.Run(ctx, mustParse(t, "OPEN:"+inPath+",rdonly"), mustParse(t, "EXEC:true,nofork"), g); err != nil {
		t.Fatal(err)
	}
	if dump.Len() != 0 {
		t.Fatalf("nofork dumped FDs: %q", dump.String())
	}
	if strings.Contains(stderr.String(), "switching to syslog") {
		t.Fatalf("nofork switched to syslog: %q", stderr.String())
	}
	rec.mu.Lock()
	n := rec.n
	rec.mu.Unlock()
	if n != 0 {
		t.Fatalf("nofork dialed syslog %d times", n)
	}

	stderr.Reset()
	dump.Reset()
	err := xio.Run(ctx, mustParse(t, "OPEN:"+inPath+",rdonly"), mustParse(t, "EXEC:/no/such/socat-nofork-missing,nofork"), g)
	if err == nil {
		t.Fatal("expected missing command to fail")
	}
	g.Log.Errorf("%s", err)
	rec.mu.Lock()
	n = rec.n
	msgs := append([]string(nil), rec.msg...)
	rec.mu.Unlock()
	if n != 0 || len(msgs) != 0 {
		t.Fatalf("failed nofork used syslog dials=%d msg=%v", n, msgs)
	}
	if strings.Contains(stderr.String(), "switching to syslog") {
		t.Fatalf("failed nofork switched: %q", stderr.String())
	}
	if !strings.Contains(stderr.String(), "no/such/socat-nofork-missing") {
		t.Fatalf("exec failure missing from stderr: %q", stderr.String())
	}
}
