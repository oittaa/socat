package logx

import (
	"bytes"
	"runtime"
	"strings"
	"sync"
	"testing"
)

type recordedSyslog struct {
	mu  sync.Mutex
	tag string
	fac string
	pri []string
	msg []string
}

func (r *recordedSyslog) add(pri, msg string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.pri = append(r.pri, pri)
	r.msg = append(r.msg, msg)
	return nil
}

func (r *recordedSyslog) Crit(s string) error    { return r.add("crit", s) }
func (r *recordedSyslog) Err(s string) error     { return r.add("err", s) }
func (r *recordedSyslog) Warning(s string) error { return r.add("warning", s) }
func (r *recordedSyslog) Notice(s string) error  { return r.add("notice", s) }
func (r *recordedSyslog) Info(s string) error    { return r.add("info", s) }
func (r *recordedSyslog) Debug(s string) error   { return r.add("debug", s) }
func (r *recordedSyslog) Close() error           { return nil }

func TestSyslogSeverityMapping(t *testing.T) {
	rec := &recordedSyslog{}
	restore := SetSyslogDial(func(tag, fac string) (SyslogWriter, error) {
		rec.tag = tag
		rec.fac = fac
		return rec, nil
	})
	t.Cleanup(restore)

	w, err := DialSyslog("socat", "local1")
	if err != nil {
		t.Fatal(err)
	}
	if rec.tag != "socat" || rec.fac != "local1" {
		t.Fatalf("dial tag=%q fac=%q", rec.tag, rec.fac)
	}
	log := New()
	log.SetLevel(Debug)
	log.SetSyslog(w)
	log.Fatalf("fatal-msg")
	log.Errorf("error-msg")
	log.Warningf("warn-msg")
	log.Noticef("notice-msg")
	log.Infof("info-msg")
	log.Debugf("debug-msg")
	want := []struct{ pri, msg string }{
		{"crit", "F fatal-msg"},
		{"err", "E error-msg"},
		{"warning", "W warn-msg"},
		{"notice", "N notice-msg"},
		{"info", "I info-msg"},
		{"debug", "D debug-msg"},
	}
	rec.mu.Lock()
	defer rec.mu.Unlock()
	if len(rec.pri) != len(want) {
		t.Fatalf("got %v %v", rec.pri, rec.msg)
	}
	for i, row := range want {
		if rec.pri[i] != row.pri || rec.msg[i] != row.msg {
			t.Errorf("%d: %s %q want %s %q", i, rec.pri[i], rec.msg[i], row.pri, row.msg)
		}
	}
}

func TestCloneSwitchDoesNotMoveParent(t *testing.T) {
	var parentOut bytes.Buffer
	parent := New()
	parent.SetOutput(&parentOut)
	parent.SetLevel(Debug)
	child := parent.Clone()
	rec := &recordedSyslog{}
	child.SetSyslog(rec)
	child.Errorf("child")
	parent.Errorf("parent")
	if parent.UsingSyslog() {
		t.Fatal("parent switched")
	}
	if !strings.Contains(parentOut.String(), " E parent") {
		t.Fatalf("parent stderr=%q", parentOut.String())
	}
	if strings.Contains(parentOut.String(), "child") {
		t.Fatalf("child leaked to parent stderr: %q", parentOut.String())
	}
	rec.mu.Lock()
	defer rec.mu.Unlock()
	if len(rec.msg) != 1 || rec.msg[0] != "E child" {
		t.Fatalf("child syslog=%v", rec.msg)
	}
}

func TestCloseOwnedSyslogLeavesParentWriter(t *testing.T) {
	parentRec := &recordedSyslog{}
	parent := New()
	parent.SetSyslog(parentRec)
	child := parent.Clone()
	childRec := &recordedSyslog{}
	child.SetSyslog(childRec)
	child.CloseOwnedSyslog()
	parent.Errorf("still-parent")
	parentRec.mu.Lock()
	defer parentRec.mu.Unlock()
	if len(parentRec.msg) != 1 || parentRec.msg[0] != "E still-parent" {
		t.Fatalf("parent syslog=%v", parentRec.msg)
	}
}

func TestDialSyslogRejectedOnWindows(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip()
	}
	_, err := DialSyslog("socat", "daemon")
	if err == nil || !strings.Contains(err.Error(), "not implemented") {
		t.Fatalf("err=%v", err)
	}
}
