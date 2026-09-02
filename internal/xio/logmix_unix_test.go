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

type mixRecorder struct {
	mu  sync.Mutex
	n   int
	msg []string
}

func (r *mixRecorder) add(_ string, msg string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.msg = append(r.msg, msg)
	return nil
}
func (r *mixRecorder) Crit(s string) error    { return r.add("crit", s) }
func (r *mixRecorder) Err(s string) error     { return r.add("err", s) }
func (r *mixRecorder) Warning(s string) error { return r.add("warning", s) }
func (r *mixRecorder) Notice(s string) error  { return r.add("notice", s) }
func (r *mixRecorder) Info(s string) error    { return r.add("info", s) }
func (r *mixRecorder) Debug(s string) error   { return r.add("debug", s) }
func (r *mixRecorder) Close() error           { return nil }

func installMixSyslog(t *testing.T) *mixRecorder {
	t.Helper()
	rec := &mixRecorder{}
	restore := logx.SetSyslogDial(func(tag, fac string) (logx.SyslogWriter, error) {
		rec.mu.Lock()
		rec.n++
		rec.mu.Unlock()
		return rec, nil
	})
	t.Cleanup(restore)
	return rec
}

func TestMixedLogSwitchesAfterBothEndpointsOpen(t *testing.T) {
	rec := installMixSyslog(t)
	var stderr bytes.Buffer
	log := logx.New()
	log.SetOutput(&stderr)
	log.SetLevel(logx.Info)
	g := &xio.Global{
		Log:         log,
		BlockSize:   8192,
		Linger:      10 * time.Millisecond,
		LeftToRight: true,
		LogMixed:    true,
		LogFacility: "daemon",
		Progname:    "socat",
	}
	missing := filepath.Join(t.TempDir(), "missing")
	inPath := filepath.Join(t.TempDir(), "in")
	if err := os.WriteFile(inPath, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	err := xio.Run(ctx, mustParse(t, "OPEN:"+inPath+",rdonly"), mustParse(t, "OPEN:"+missing+",rdonly"), g)
	if err == nil {
		t.Fatal("expected open failure")
	}
	if strings.Contains(stderr.String(), "switching to syslog") {
		t.Fatalf("switched before both endpoints opened: %q", stderr.String())
	}
	rec.mu.Lock()
	n := rec.n
	rec.mu.Unlock()
	if n != 0 {
		t.Fatalf("syslog dialed %d times on failed open", n)
	}

	outPath := filepath.Join(t.TempDir(), "out")
	if err := os.WriteFile(outPath, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	stderr.Reset()
	if err := xio.Run(ctx, mustParse(t, "OPEN:"+inPath+",rdonly"), mustParse(t, "OPEN:"+outPath+",wronly"), g); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(stderr.String(), "switching to syslog") {
		t.Fatalf("stderr=%q", stderr.String())
	}
	if strings.Contains(stderr.String(), "is at EOF") {
		t.Fatalf("EOF leaked to stderr after switch: %q", stderr.String())
	}
	rec.mu.Lock()
	defer rec.mu.Unlock()
	foundEOF := false
	for _, msg := range rec.msg {
		if strings.Contains(msg, "is at EOF") {
			foundEOF = true
		}
	}
	if rec.n != 1 || !foundEOF {
		t.Fatalf("syslog dials=%d msg=%v", rec.n, rec.msg)
	}
}

func TestMixedLogForkSessionsSwitchIndependently(t *testing.T) {
	rec := installMixSyslog(t)
	var stderr bytes.Buffer
	log := logx.New()
	log.SetOutput(&stderr)
	log.SetLevel(logx.Info)
	g := &xio.Global{
		Log:         log,
		BlockSize:   8192,
		Linger:      50 * time.Millisecond,
		LogMixed:    true,
		LogFacility: "local0",
		Progname:    "socat",
	}
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	lo := startForkListenPIPE(t, ctx, g, "TCP4-LISTEN:0,fork,reuseaddr")
	if log.UsingSyslog() {
		t.Fatal("parent listener switched to syslog")
	}
	port := listenerPort(t, lo)
	addr := net.JoinHostPort("127.0.0.1", strconv.Itoa(port))
	for range 2 {
		c := openClient(t, ctx, cloneGlobal(g), "TCP4:"+addr)
		mustWrite(t, c.Stream, []byte("ab"))
		_ = readFull(t, c.Stream, 2)
		_ = c.Close()
	}
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		rec.mu.Lock()
		n := rec.n
		rec.mu.Unlock()
		if n == 2 && strings.Count(stderr.String(), "switching to syslog") == 2 && !log.UsingSyslog() {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	rec.mu.Lock()
	n := rec.n
	rec.mu.Unlock()
	t.Fatalf("dials=%d parentSyslog=%v stderr=%q", n, log.UsingSyslog(), stderr.String())
}
