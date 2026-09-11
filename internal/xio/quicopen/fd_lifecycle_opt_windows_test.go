//go:build windows

package quicopen

func fdLifecycleOption() string { return "noinherit=1" }
