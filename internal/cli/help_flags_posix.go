//go:build linux || darwin

package cli

import "github.com/oittaa/socat/internal/outbuf"

func printHelpDumpFlag(b *outbuf.Buf) {
	b.Printf("  -D              analyze file descriptors before transfer\n")
}

func printHelpSyslogFlags(b *outbuf.Buf) {
	b.Printf("  -ly[facility]   log to syslog, using facility (default is daemon)\n")
	b.Printf("  -lm[facility]   mixed log mode (stderr during initialization, then syslog)\n")
}

func syslogOptionSupported() bool { return true }

func dumpFDOptionSupported() bool { return true }
