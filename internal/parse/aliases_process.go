package parse

func init() {
	registerOptionAliases(map[string]string{
		"wait-slave":    "pty-wait-slave",
		"waitslave":     "pty-wait-slave",
		"pty-intervall": "pty-interval",
		"winsz":         "tiocswinsz",
		"tiocsctty":     "ctty",
		"symbolic-link": "link",
		"cd":            "chdir",
		"sid":           "setsid",
		"login":         "dash",
		"pgid":          "setpgid",
		"close":         "end-close",
		// raw is a distinct TERMIOS combination; it does not use the cfmakeraw mask
		// (raw leaves ECHO unchanged). Keep raw canonical so ApplyTermios can
		// preserve that behavior.
		"termios-cfmakeraw": "cfmakeraw",
		"termios-rawer":     "rawer",
		"setflags":          "termios-setflags",
		"crterase":          "echoe",
		"crtkill":           "echoke",
		"ctlecho":           "echoctl",
		"hup":               "hupcl",
		"prterase":          "echoprt",
		"tandem":            "ixoff",
		// TERMIOS c_cc nicknames fold onto v* canonical names.
		"intr":    "vintr",
		"quit":    "vquit",
		"erase":   "verase",
		"kill":    "vkill",
		"eof":     "veof",
		"eol":     "veol",
		"eol2":    "veol2",
		"min":     "vmin",
		"time":    "vtime",
		"start":   "vstart",
		"stop":    "vstop",
		"susp":    "vsusp",
		"werase":  "vwerase",
		"lnext":   "vlnext",
		"discard": "vdiscard",
		"reprint": "vreprint",
		"rprnt":   "vreprint",
		"swtc":    "vswtc",
		"swtch":   "vswtc",
	})
}
