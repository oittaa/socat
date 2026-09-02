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
	mu       *sync.Mutex
	out      io.Writer
	level    Level // maximum level printed (inclusive)
	shutup   int   // fork-child severity demotion (classic children-shutup)
	progname string
	micros   bool
	hostname string
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
	child := *l
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
	child := *l
	return &child
}

// SetOutput sets the log destination.
func (l *Logger) SetOutput(w io.Writer) { l.out = w }

// SetLevel sets the maximum severity that is printed.
func (l *Logger) SetLevel(level Level) { l.level = level }

// Level returns the current maximum severity.
func (l *Logger) Level() Level { return l.level }

// SetProgname sets the program name used in messages (-lp).
func (l *Logger) SetProgname(name string) { l.progname = name }

// SetMicros enables microsecond timestamps (-lu).
func (l *Logger) SetMicros(v bool) { l.micros = v }

// SetHostname prefixes messages with a hostname (-lh).
func (l *Logger) SetHostname(h string) { l.hostname = h }

// Increase bumps verbosity by one level (each -d).
func (l *Logger) Increase() {
	if l.level < Debug {
		l.level++
	}
}

func (l *Logger) logf(level Level, format string, args ...any) {
	level += Level(l.shutup)
	if level > Debug {
		return
	}
	if level > l.level {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()

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
