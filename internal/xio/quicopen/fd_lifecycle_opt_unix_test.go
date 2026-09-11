//go:build linux || darwin

package quicopen

func fdLifecycleOption() string { return "append" }
