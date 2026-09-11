//go:build linux || darwin

package netopen

func fdLifecycleOption() string { return "append" }
