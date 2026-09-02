package logx

// SyslogWriter is the subset of a syslog client used for diagnostic output.
type SyslogWriter interface {
	Crit(string) error
	Err(string) error
	Warning(string) error
	Notice(string) error
	Info(string) error
	Debug(string) error
	Close() error
}

var syslogDial = defaultSyslogDial

// DialSyslog opens a syslog destination using tag as the syslog identity.
func DialSyslog(tag, facility string) (SyslogWriter, error) {
	name, err := CanonicalFacility(facility)
	if err != nil {
		return nil, err
	}
	if tag == "" {
		tag = "socat"
	}
	return syslogDial(tag, name)
}

// SetSyslogDial replaces the syslog constructor. Tests use this to capture
// messages without talking to a system logger. The returned function restores
// the previous constructor.
func SetSyslogDial(fn func(tag, facility string) (SyslogWriter, error)) func() {
	prev := syslogDial
	if fn == nil {
		syslogDial = defaultSyslogDial
	} else {
		syslogDial = fn
	}
	return func() { syslogDial = prev }
}

func writeSyslog(w SyslogWriter, level Level, msg string) {
	if w == nil {
		return
	}
	text := levelNames[level] + " " + msg
	switch level {
	case Fatal:
		_ = w.Crit(text)
	case Error:
		_ = w.Err(text)
	case Warning:
		_ = w.Warning(text)
	case Notice:
		_ = w.Notice(text)
	case Info:
		_ = w.Info(text)
	default:
		_ = w.Debug(text)
	}
}
