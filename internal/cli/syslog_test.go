package cli

import (
	"bytes"
	"runtime"
	"strings"
	"testing"

	"github.com/oittaa/socat/internal/logx"
)

func TestSetupLoggerSyslogFromInit(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip()
	}
	rec := &cliRecordedSyslog{}
	restore := logx.SetSyslogDial(func(tag, fac string) (logx.SyslogWriter, error) {
		rec.tag, rec.fac = tag, fac
		return rec, nil
	})
	t.Cleanup(restore)
	cfg, err := ParseArgs([]string{"-lylocal2", "-lp", "mysocat", "STDIN", "STDOUT"})
	if err != nil {
		t.Fatal(err)
	}
	log, closeLog, err := setupLogger(cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(closeLog)
	if !log.UsingSyslog() {
		t.Fatal("expected syslog destination")
	}
	log.Errorf("from-init")
	if rec.tag != "mysocat" || rec.fac != "local2" {
		t.Fatalf("tag=%q fac=%q", rec.tag, rec.fac)
	}
	if len(rec.msg) != 1 || rec.msg[0] != "E from-init" {
		t.Fatalf("msg=%v", rec.msg)
	}
}

func TestSetupLoggerMixedStaysOnStderrUntilSwitch(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip()
	}
	rec := &cliRecordedSyslog{}
	restore := logx.SetSyslogDial(func(tag, fac string) (logx.SyslogWriter, error) {
		rec.tag, rec.fac = tag, fac
		return rec, nil
	})
	t.Cleanup(restore)
	cfg, err := ParseArgs([]string{"-lm", "STDIN", "STDOUT"})
	if err != nil {
		t.Fatal(err)
	}
	log, closeLog, err := setupLogger(cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(closeLog)
	if log.UsingSyslog() {
		t.Fatal("mixed mode must start on stderr")
	}
	var buf bytes.Buffer
	log.SetOutput(&buf)
	log.Errorf("still-stderr")
	if len(rec.msg) != 0 {
		t.Fatalf("syslog received %v", rec.msg)
	}
	if !strings.Contains(buf.String(), " E still-stderr") {
		t.Fatalf("stderr=%q", buf.String())
	}
}

type cliRecordedSyslog struct {
	tag, fac string
	msg      []string
}

func (r *cliRecordedSyslog) add(_ string, msg string) error {
	r.msg = append(r.msg, msg)
	return nil
}
func (r *cliRecordedSyslog) Crit(s string) error    { return r.add("crit", s) }
func (r *cliRecordedSyslog) Err(s string) error     { return r.add("err", s) }
func (r *cliRecordedSyslog) Warning(s string) error { return r.add("warning", s) }
func (r *cliRecordedSyslog) Notice(s string) error  { return r.add("notice", s) }
func (r *cliRecordedSyslog) Info(s string) error    { return r.add("info", s) }
func (r *cliRecordedSyslog) Debug(s string) error   { return r.add("debug", s) }
func (r *cliRecordedSyslog) Close() error           { return nil }
