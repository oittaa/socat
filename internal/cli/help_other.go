//go:build linux

package cli

func hideOpt(name string) bool {
	switch name {
	case "binary", "text", "noinherit":
		return true
	default:
		return false
	}
}
