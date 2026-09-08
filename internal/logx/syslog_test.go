package logx

import (
	"runtime"
	"strings"
	"sync"
	"testing"
)

type recordedSyslog struct {
	mu  sync.Mutex
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
