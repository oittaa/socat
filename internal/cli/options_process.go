package cli

// EXEC/SYSTEM/SHELL, PTY, and TERMIOS options.
func processOptionGroups() []helpOptGroup {
	return []helpOptGroup{
		{"EXEC, SYSTEM, SHELL", []helpOpt{
			{name: "pipes", desc: "connect with pipes"},
			{name: "pty", desc: "run on a pseudo-terminal"},
			{name: "setsid", desc: "new session", aliases: []string{"sid"}},
			{name: "dash", desc: "prefix child argv[0] with '-' (login shell)", aliases: []string{"login"}},
			{name: "setpgid", desc: "setpgid(0, pgid) in the child (PH_LATE)", aliases: []string{"pgid"}, validate: validateOptionalSignedInteger},
			{name: "stderr", desc: "include child stderr"},
			{name: "fdin", desc: "child stdin fd number", validate: validateInteger(0)},
			{name: "fdout", desc: "child stdout fd number", validate: validateInteger(0)},
			{name: "shell", desc: "use a shell"},
			{name: "chdir", desc: "change directory before open or exec", aliases: []string{"cd"}, validate: validateRequiredString},
			{name: "shut-none", desc: "do not half-close; do not kill EXEC child on close", validate: validateOptionalBool},
			{name: "shut-down", desc: "shutdown(SHUT_WR) instead of the address default", validate: validateOptionalBool},
			{name: "shut-close", desc: "fully close instead of half-closing", validate: validateOptionalBool},
			{name: "end-close", desc: "close on EOF", aliases: []string{"close"}},
			{name: "shut", desc: "half-close mode (none, down, close, or null)", validate: validateShutOption},
			{name: "shut-null", desc: "0-byte datagram as half-close", validate: validateOptionalBool},
		}},
		{"PTY and TERMIOS", []helpOpt{
			{name: "link", desc: "symlink to the PTY slave", aliases: []string{"symbolic-link"}},
			{name: "raw", desc: "obsolete classic raw termios mode"},
			{name: "cfmakeraw", desc: "raw termios (cfmakeraw)", aliases: []string{"termios-cfmakeraw"}},
			{name: "rawer", desc: "stricter raw termios", aliases: []string{"termios-rawer"}},
			{name: "sane", desc: "reset termios to sane defaults"},
			{name: "echo", desc: "terminal echo"},
			{name: "echoe", desc: "ECHOE", aliases: []string{"crterase"}},
			{name: "echoke", desc: "ECHOKE", aliases: []string{"crtkill"}},
			{name: "echoctl", desc: "ECHOCTL", aliases: []string{"ctlecho"}},
			{name: "hupcl", desc: "HUPCL", aliases: []string{"hup"}},
			{name: "ixoff", desc: "IXOFF", aliases: []string{"tandem"}},
			{name: "opost", desc: "output post-processing"},
			{name: "ispeed", desc: "input baud"},
			{name: "ospeed", desc: "output baud"},
			{name: "tiocswinsz", desc: "window size cols:rows", aliases: []string{"winsz"}},
			{name: "pty-wait-slave", desc: "wait until the slave is open", aliases: []string{"wait-slave", "waitslave"}},
			{name: "pty-interval", desc: "poll interval while waiting for slave", aliases: []string{"pty-intervall"}, validate: validateDurationOption},
			{name: "ctty", desc: "make the PTY the controlling tty", aliases: []string{"tiocsctty"}},
			// Classic compat spellings: accepted as no-ops. The PTY master
			// always comes from the platform default (/dev/ptmx or openpty),
			// so both spellings already describe what we do.
			{name: "ptmx", desc: "compat: /dev/ptmx is the default"},
			{name: "openpty", desc: "compat: openpty(3) semantics are the default"},
			{name: "escape", desc: "escape character"},
		}},
	}
}
