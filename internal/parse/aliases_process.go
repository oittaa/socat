package parse

func init() {
	registerOptionAliases(map[string]string{
		"wait-slave":    "pty-wait-slave",
		"waitslave":     "pty-wait-slave",
		"pty-intervall": "pty-interval",
		"winsz":         "tiocswinsz",
		"tiocsctty":     "ctty",
	})
}
