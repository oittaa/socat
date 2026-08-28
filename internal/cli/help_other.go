//go:build linux

package cli

func hideOpt(name string) bool {
	switch name {
	case "binary", "text", "noinherit",
		"nopush", "noopt", "tcp-nopush", "tcp-noopt":
		return true
	default:
		return false
	}
}
