// Package logx provides severity-based logging compatible with classic socat -d levels.
package logx

import (
	"fmt"
	"io"
	"os"
	"sync"
	"time"
)

// Level matches classic socat diagnostic levels.
type Level int

const (
	Fatal Level = iota
	Error
	Warning
	Notice
	Info
	Debug
)

var levelNames = [...]string{"F", "E", "W", "N", "I", "D"}

// Logger is a simple concurrent-safe socat-style logger.
type Logger struct {
	mu          *sync.Mutex
	out         io.Writer
	syslog      SyslogWriter
	syslogOwned bool  // true when this logger opened syslog and must close it
	level       Level // maximum level printed (inclusive)
	shutup      int   // fork-child severity demotion (classic children-shutup)
	progname    string
	micros      bool
	hostname    string
}

// New creates a logger writing to stderr at Warning level (classic default: fatal/error/warning).
func New() *Logger {
	return &Logger{
		mu:       &sync.Mutex{},
		out:      os.Stderr,
		level:    Warning,
		progname: "socat",
	}
}

// WithShutup returns a child logger that shares the output lock while
// demoting messages by n severity levels. The parent logger is unchanged.
func (l *Logger) WithShutup(n int) *Logger {
	if l == nil {
		return nil
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	child := *l
	child.syslogOwned = false
	if n > 0 {
		child.shutup += n
	}
	return &child
}

// Clone returns a logger that shares the output lock and current destination
// but can later switch destinations without changing the parent.
func (l *Logger) Clone() *Logger {
	if l == nil {
		return nil
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	child := *l
	child.syslogOwned = false
	return &child
}

// SetSyslog sends later messages to syslog instead of the writer.
func (l *Logger) SetSyslog(w SyslogWriter) {
	if l == nil {
		return
	}
	l.mu.Lock()
	if l.syslogOwned && l.syslog != nil && l.syslog != w {
		_ = l.syslog.Close()
	}
	l.syslog = w
	l.syslogOwned = w != nil
	l.mu.Unlock()
}

// CloseOwnedSyslog closes a syslog destination this logger opened.
func (l *Logger) CloseOwnedSyslog() {
	if l == nil {
		return
	}
	l.mu.Lock()
	owned := l.syslogOwned
	l.mu.Unlock()
	if owned {
		l.SetSyslog(nil)
	}
}

// UseSyslog opens a syslog destination and switches this logger to it.
func (l *Logger) UseSyslog(tag, facility string) error {
	w, err := DialSyslog(tag, facility)
	if err != nil {
		return err
	}
	l.SetSyslog(w)
	return nil
}

// UsingSyslog reports whether messages currently go to syslog.
func (l *Logger) UsingSyslog() bool {
	if l == nil {
		return false
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.syslog != nil
}

// SetOutput sets the log destination.
func (l *Logger) SetOutput(w io.Writer) {
	if l == nil {
		return
	}
	l.mu.Lock()
	l.out = w
	l.mu.Unlock()
}

// SetLevel sets the maximum severity that is printed.
func (l *Logger) SetLevel(level Level) {
	if l == nil {
		return
	}
	l.mu.Lock()
	l.level = level
	l.mu.Unlock()
}

// Level returns the current maximum severity.
func (l *Logger) Level() Level {
	if l == nil {
		return Fatal
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.level
}

// SetProgname sets the program name used in messages (-lp).
func (l *Logger) SetProgname(name string) {
	if l == nil {
		return
	}
	l.mu.Lock()
	l.progname = name
	l.mu.Unlock()
}

// SetMicros enables microsecond timestamps (-lu).
func (l *Logger) SetMicros(v bool) {
	if l == nil {
		return
	}
	l.mu.Lock()
	l.micros = v
	l.mu.Unlock()
}

// SetHostname prefixes messages with a hostname (-lh).
func (l *Logger) SetHostname(h string) {
	if l == nil {
		return
	}
	l.mu.Lock()
	l.hostname = h
	l.mu.Unlock()
}

// Increase bumps verbosity by one level (each -d).
func (l *Logger) Increase() {
	if l == nil {
		return
	}
	l.mu.Lock()
	if l.level < Debug {
		l.level++
	}
	l.mu.Unlock()
}

func (l *Logger) logf(level Level, format string, args ...any) {
	if l == nil {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	level += Level(l.shutup)
	if level > Debug {
		return
	}
	if level > l.level {
		return
	}

	if l.syslog != nil {
		writeSyslog(l.syslog, level, fmt.Sprintf(format, args...))
		return
	}
	if l.out == nil {
		return
	}

	now := time.Now()
	var ts string
	if l.micros {
		ts = now.Format("2006/01/02 15:04:05.000000")
	} else {
		ts = now.Format("2006/01/02 15:04:05")
	}

	// Classic format: "YYYY/MM/DD HH:MM:SS [hostname ]progname[pid] L message"
	// so test.sh can grep e.g. `E unknown device/address`.
	host := ""
	if l.hostname != "" {
		host = l.hostname + " "
	}
	msg := fmt.Sprintf(format, args...)
	if _, err := fmt.Fprintf(l.out, "%s %s%s[%d] %s %s\n",
		ts, host, l.progname, os.Getpid(), levelNames[level], msg); err != nil {
		return
	}
}

func (l *Logger) Fatalf(format string, args ...any)   { l.logf(Fatal, format, args...) }
func (l *Logger) Errorf(format string, args ...any)   { l.logf(Error, format, args...) }
func (l *Logger) Warningf(format string, args ...any) { l.logf(Warning, format, args...) }
func (l *Logger) Noticef(format string, args ...any)  { l.logf(Notice, format, args...) }
func (l *Logger) Infof(format string, args ...any)    { l.logf(Info, format, args...) }
func (l *Logger) Debugf(format string, args ...any)   { l.logf(Debug, format, args...) }
