package cli

// EXEC/SYSTEM/SHELL, PTY, and TERMIOS options.
func processOptionGroups() []helpOptGroup {
	return []helpOptGroup{
		{"EXEC, SYSTEM, SHELL", []helpOpt{
			{name: "pipes", desc: "connect with pipes"},
			{name: "pty", desc: "run on a pseudo-terminal"},
			{name: "setsid", desc: "new session"},
			{name: "stderr", desc: "include child stderr"},
			{name: "fdin", desc: "child stdin fd number", validate: validateInteger(0)},
			{name: "fdout", desc: "child stdout fd number", validate: validateInteger(0)},
			{name: "shell", desc: "use a shell"},
			{name: "chdir", desc: "change directory before open or exec", validate: validateRequiredString},
			{name: "shut-none", desc: "do not kill the child on close"},
			{name: "shut-close", desc: "fully close instead of half-closing"},
			{name: "end-close", desc: "close on EOF"},
			{name: "shut", desc: "half-close mode"},
			{name: "shut-null", desc: "0-byte datagram as half-close"},
		}},
		{"PTY and TERMIOS", []helpOpt{
			{name: "link", desc: "symlink to the PTY slave", aliases: []string{"symbolic-link"}},
			{name: "cfmakeraw", desc: "raw termios (cfmakeraw(3))"},
			{name: "raw", desc: "POSIX raw termios"},
			{name: "rawer", desc: "stricter raw termios"},
			{name: "sane", desc: "reset termios to sane defaults"},
			{name: "echo", desc: "terminal echo"},
			{name: "opost", desc: "output post-processing"},
			{name: "ispeed", desc: "input baud"},
			{name: "ospeed", desc: "output baud"},
			{name: "tiocswinsz", desc: "window size cols:rows", aliases: []string{"winsz"}},
			{name: "pty-wait-slave", desc: "wait until the slave is open", aliases: []string{"wait-slave", "waitslave"}},
			{name: "pty-interval", desc: "poll interval while waiting for slave", validate: validateDurationOption},
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
