package parse

func init() {
	registerOptionAliases(map[string]string{
		"wait-slave":    "pty-wait-slave",
		"waitslave":     "pty-wait-slave",
		"pty-intervall": "pty-interval",
		"winsz":         "tiocswinsz",
		"tiocsctty":     "ctty",
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
	})
}
