package logx

import (
	"io"
	"sync"
)

var (
	defaultMu  sync.Mutex
	defaultLog *Logger
)

// SetDefault records the process logger used by CloseErr and Default.
func SetDefault(l *Logger) {
	defaultMu.Lock()
	defaultLog = l
	defaultMu.Unlock()
}

// Default returns the process logger recorded by SetDefault, or nil.
func Default() *Logger {
	defaultMu.Lock()
	defer defaultMu.Unlock()
	return defaultLog
}

// CloseQuiet closes c and logs a failed close at debug level.
func CloseQuiet(c io.Closer) {
	if c == nil {
		return
	}
	CloseErr(c.Close())
}

// CloseErr inspects a close error so callers do not need #nosec G104.
// The first operation error stays the returned error; this only logs.
func CloseErr(err error) {
	if err == nil {
		return
	}
	defaultMu.Lock()
	l := defaultLog
	defaultMu.Unlock()
	if l != nil {
		l.Debugf("close: %v", err)
	}
}
