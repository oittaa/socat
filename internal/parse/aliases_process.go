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
		// raw is a distinct classic optdesc (Canonical "raw") with the same
		// TERMIOS/FD groups as cfmakeraw. Help already lists it as an alias
		// of cfmakeraw (same applyCombo; tag-1.8.1.3
		// 12c08bf66d709fba17035ce95d85bd218428d9ba). Fold at parse so
		// last-option-wins matches that help table.
		"raw":               "cfmakeraw",
		"termios-cfmakeraw": "cfmakeraw",
		"termios-rawer":     "rawer",
		"crterase":          "echoe",
		"crtkill":           "echoke",
		"ctlecho":           "echoctl",
		"hup":               "hupcl",
		"tandem":            "ixoff",
	})
}
