package cli

import (
	"io"

	"github.com/oittaa/socat"
	"github.com/oittaa/socat/internal/outbuf"
	"github.com/oittaa/socat/internal/xio"
)

// hideDarwinOnlyIPRecv hides ip-recvdstaddr / ip-recvif (and aliases) on every
// GOOS except macOS. Runtime support is macOS-only (IP_RECVDSTADDR /
// IP_RECVIF cmsg extraction); Linux and Windows must not advertise names they reject.
func hideDarwinOnlyIPRecv(name, goos string) bool {
	switch name {
	case "ip-recvdstaddr", "ip-recvif", "recvdstaddr", "iprecvdstaddr", "recvif":
		return goos != "darwin"
	default:
		return false
	}
}

// hideLinuxOnlyRemainingIPv4 hides Linux-only remaining IPv4 options
// (ip-retopts recv ancillary and ip-router-alert) except on Linux. macOS
// IP_RETOPTS is an IP-options blob, not Linux's recv flag.
func hideLinuxOnlyRemainingIPv4(name, goos string) bool {
	switch name {
	case "ip-retopts", "ipretopts", "retopts",
		"ip-router-alert", "iprouteralert", "routeralert":
		return goos != "linux"
	default:
		return false
	}
}

// hideLinuxOnlyIPv6RecvExt hides ipv6-recvdstopts / ipv6-recvhopopts except
// on Linux. Darwin accepts setsockopt for those names but getsockopt stays 0.
// ipv6-recvrthdr / ipv6-recvpathmtu are advertised on Darwin.
func hideLinuxOnlyIPv6RecvExt(name, goos string) bool {
	switch name {
	case "ipv6-recvdstopts", "recvdstopts",
		"ipv6-recvhopopts", "recvhopopts":
		return goos != "linux"
	default:
		return false
	}
}

func hideOptGroup(title string) bool {
	switch title {
	case "PTY and TERMIOS":
		return !xio.FeaturePTY && !xio.FeatureTERMIOS
	case "POSIX message queues":
		return !xio.FeaturePOSIXMQ
	case "TUN and INTERFACE":
		return !xio.FeatureTUN && !xio.FeatureINTERFACE
	case "Namespaces":
		return !xio.FeatureNAMESPACES
	default:
		return false
	}
}

func printHelp(w io.Writer, level int) error {
	var b outbuf.Buf
	b.Printf("socat %s by oittaa — multipurpose relay (Go)\n\n", socat.Version)
	b.Printf("Usage:\n")
	b.Printf("  socat [options] <address> <address>\n")
	b.Printf("  socat -V | -h | -hh | -hhh\n\n")
	b.Printf("  <address> is TYPE:params,option=value,...\n")
	b.Printf("  Use - for STDIO.  -h lists types; -hh lists options; -hhh adds aliases.\n\n")
	b.Printf("Example (TLS tunnel in front of a plain TCP service):\n")
	b.Printf("  socat TLS-LISTEN:8443,reuseaddr,fork,cert=s.crt,key=s.key,verify=0 TCP:127.0.0.1:8080\n\n")

	printHelpFlags(&b)
	printHelpAddresses(&b, level >= 3)
	if level >= 2 {
		printHelpOptions(&b, level >= 3)
	}
	return b.Flush(w)
}

func printHelpFlags(b *outbuf.Buf) {
	b.Printf("Options:\n")
	b.Printf("  -V              print version and features\n")
	b.Printf("  -h|-?           print help\n")
	b.Printf("  -hh             help plus honored address options\n")
	b.Printf("  -hhh            help plus options, aliases, and termios names\n")
	b.Printf("  -d|-d0..-d4     increase verbosity\n")
	b.Printf("  -v              verbose data dump (text)\n")
	b.Printf("  -x              verbose data dump (hex)\n")
	b.Printf("  -b<size>        transfer block size (default 8192)\n")
	b.Printf("  -t<time>        linger after EOF (default 0.5s)\n")
	b.Printf("  -T<time>        inactivity timeout\n")
	b.Printf("  -S<mask>        log these signal numbers (bitmap)\n")
	b.Printf("  -u              unidirectional left→right\n")
	b.Printf("  -U              unidirectional right→left\n")
	// test.sh OPTION_RAW_DUMP greps [[:space:]]-[rR][[:space:]]; keep the spaces.
	b.Printf("  -r <file>       dump left-to-right raw data\n")
	b.Printf("  -R <file>       dump right-to-left raw data\n")
	// test.sh greps [[:space:]]-4[[:space:]], -6, -0 on separate lines.
	b.Printf("  -4     prefer IPv4 if version is not explicitly specified\n")
	b.Printf("  -6     prefer IPv6 if version is not explicitly specified\n")
	b.Printf("  -0     do not prefer an IP version\n")
	b.Printf("  --statistics   output transfer statistics on exit\n")
	b.Printf("  --experimental allow experimental options (netns)\n")
}

func printHelpAddresses(b *outbuf.Buf, aliases bool) {
	b.Printf("\nAddress types:\n")
	for _, g := range xio.HelpAddressGroups() {
		width := 0
		for _, a := range g.Addrs {
			if n := len(a.Syntax); n > width {
				width = n
			}
			if aliases {
				for _, al := range a.Aliases {
					if n := len(al); n > width {
						width = n
					}
				}
			}
		}
		if len(g.Addrs) == 0 {
			continue
		}
		b.Printf("\n  %s\n", g.Title)
		for _, a := range g.Addrs {
			b.Printf("    %-*s  %s\n", width, a.Syntax, a.Desc)
			if aliases {
				for _, al := range a.Aliases {
					printOptLine(b, al, "alias of "+a.Name, width)
				}
			}
		}
	}
}

func printHelpOptions(b *outbuf.Buf, all bool) {
	b.Printf("\nAddress options:\n")
	b.Printf("  Form: option or option=value. Only honored names are listed.\n")
	groups := helpOptionGroups()
	width := 0
	for _, g := range groups {
		if hideOptGroup(g.title) {
			continue
		}
		for _, o := range g.opts {
			if hideOpt(o.name) {
				continue
			}
			if n := len(o.name); n > width {
				width = n
			}
			if all {
				for _, al := range o.aliases {
					if n := len(al); n > width {
						width = n
					}
				}
			}
		}
	}
	extra := extraHelpNames(all)
	for _, name := range extra {
		if n := len(name); n > width {
			width = n
		}
	}
	for _, g := range groups {
		if hideOptGroup(g.title) {
			continue
		}
		printedTitle := false
		for _, o := range g.opts {
			if hideOpt(o.name) {
				continue
			}
			if !printedTitle {
				b.Printf("\n  %s\n", g.title)
				printedTitle = true
			}
			desc := o.desc
			if o.dynamicDesc != nil {
				desc = o.dynamicDesc()
			}
			printOptLine(b, o.name, desc, width)
			if all {
				for _, al := range o.aliases {
					printOptLine(b, al, "alias of "+o.name, width)
				}
			}
		}
	}
	if len(extra) == 0 {
		return
	}
	b.Printf("\n  Termios and baud (PTY / TTY)\n")
	for _, name := range extra {
		printOptLine(b, name, "termios flag or baud name", width)
	}
}

func printOptLine(b *outbuf.Buf, name, desc string, width int) {
	// Space on both sides of the name: test.sh testoptions and e2e use
	// [^a-z0-9-]<name>[^a-z0-9-] / " "+name+" ".
	b.Printf("    %-*s  %s\n", width, name, desc)
}

func extraHelpNames(all bool) []string {
	if !all {
		return nil
	}
	skip := map[string]struct{}{}
	for _, g := range helpOptionGroups() {
		for _, o := range g.opts {
			skip[o.name] = struct{}{}
			for _, al := range o.aliases {
				skip[al] = struct{}{}
			}
		}
	}
	var out []string
	for _, name := range xio.TermiosHelpNames() {
		if _, dup := skip[name]; dup {
			continue
		}
		skip[name] = struct{}{}
		out = append(out, name)
	}
	return out
}
