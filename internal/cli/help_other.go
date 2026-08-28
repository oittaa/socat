//go:build linux

package cli

func hideOpt(name string) bool {
	if hideDarwinOnlyIPRecv(name, "linux") {
		return true
	}
	switch name {
	case "binary", "text", "noinherit",
		"nopush", "noopt", "tcp-nopush", "tcp-noopt",
		"so-sndlowat":
		return true
	default:
		return false
	}
}
