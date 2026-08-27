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
		"close":         "end-close",
		// Classic raw is a distinct, obsolete TERMIOS combination. It does
		// not use the cfmakeraw mask (notably, raw leaves ECHO unchanged).
		// Keep raw canonical so ApplyTermios can preserve that behavior.
		"termios-cfmakeraw": "cfmakeraw",
		"termios-rawer":     "rawer",
		"setflags":          "termios-setflags",
		"crterase":          "echoe",
		"crtkill":           "echoke",
		"ctlecho":           "echoctl",
		"hup":               "hupcl",
		"prterase":          "echoprt",
		"tandem":            "ixoff",
		// Newly implemented GROUP_TERMIOS c_cc names (classic optionnames[]).
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
