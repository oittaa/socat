//go:build windows

package cli

import "github.com/oittaa/socat/internal/outbuf"

func printHelpDumpFlag(*outbuf.Buf) {}

func printHelpSyslogFlags(*outbuf.Buf) {}

func syslogOptionSupported() bool { return false }

func dumpFDOptionSupported() bool { return false }
