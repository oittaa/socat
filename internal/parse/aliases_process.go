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
		"crterase":          "echoe",
		"crtkill":           "echoke",
		"ctlecho":           "echoctl",
		"hup":               "hupcl",
		"tandem":            "ixoff",
	})
}
