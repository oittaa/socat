//go:build windows

package netopen

func fdLifecycleOption() string { return "noinherit=1" }
