//go:build linux

package cli

import (
	"bytes"
	"sort"
	"strings"
	"testing"

	"github.com/oittaa/socat/internal/classiccatalog"
)

func TestLinuxHelpListsSocketBufferAndBindToDevice(t *testing.T) {
	var b bytes.Buffer
	if err := printHelp(&b, 3); err != nil {
		t.Fatal(err)
	}
	help := b.String()
	for _, name := range []string{
		"sndbuf", "rcvbuf", "sndbuf-late", "rcvbuf-late", "bindtodevice",
		"so-sndbuf", "so-rcvbuf", "so-sndbuf-late", "so-rcvbuf-late",
		"so-bindtodevice", "if", "interface",
		"so-protocol", "so-prototype", "prototype", "protocol-family", "type",
		"ip-add-membership", "add-membership", "ip-membership", "membership",
		"ipv6-join-group", "ipv6-add-membership", "join-group",
		"ip-multicast-if", "multicast-if",
		"ip-multicast-loop", "multicast-loop", "mcloop", "ipmulticastloop", "multicastloop",
		"ip-multicast-ttl", "multicast-ttl", "ipmulticastttl", "multicastttl",
		"ipv6-multicast-loop", "ipv6-mcloop", "mcloop6",
		"ip-add-source-membership", "add-source-membership", "source-membership",
		"ipv6-join-source-group", "ipv6-add-source-membership", "join-source-group",
		"ip-freebind", "freebind", "ipfreebind",
		"ip-transparent", "transparent",
		"ip-mtu-discover", "mtudiscover", "ipmtudiscover",
		"ipv6-mtu-discover", "mtudiscover6",
		"setsockopt", "setsockopt-int", "setsockopt-bin", "setsockopt-string",
		"setsockopt-listen", "setsockopt-socket", "setsockopt-connected",
		"sockopt", "sockopt-int", "sockopt-bin", "sockopt-string",
		"sockopt-listen", "sockopt-sock", "sockopt-conn",
		"broadcast", "so-broadcast",
		"vintr", "intr", "veol2", "vswtc", "swtch", "sane", "pendin", "iuclc", "nl1", "crtscts",
		"b7200", "nldly", "crdly", "tabdly", "bsdly", "vtdly", "ffdly", "csize", "xtabs",
		"echoprt", "prterase", "flusho", "termios-setflags", "setflags", "termios-rawer",
		"so-debug", "debug", "so-dontroute", "dontroute", "so-oobinline", "oobinline",
		"so-priority", "priority", "so-passcred", "passcred",
		"so-no-check", "no-check", "nocheck",
		"tcp-cork", "cork", "tcp-defer-accept", "defer-accept",
		"tcp-linger2", "linger2", "tcp-maxseg", "maxseg", "mss",
		"tcp-maxseg-late", "maxseg-late", "mss-late",
		"tcp-quickack", "quickack", "tcp-syncnt", "syncnt",
		"tcp-window-clamp", "window-clamp",
		"o-rdonly", "o-creat", "o-excl", "o-wronly", "o-rdwr", "o-trunc", "ndelay", "o-ndelay",
		"f-setlk", "lock", "bytes", "cr", "crlf", "cd", "sid", "close", "maxchildren",
		"intervall", "ipv6only", "v6only", "termios-cfmakeraw", "crterase",
		"tun-no-pi", "multicast", "proxy-auth", "resolv", "ignorecr",
		"retrieve-vlan",
		"iff-notrailers", "notrailers", "iff-master", "master",
		"iff-slave", "slave", "iff-portsel", "portsel",
		"iff-automedia", "automedia",
		"udplite-send-cscov", "udplite-recv-cscov",
		"sctp-nodelay", "sctp-maxseg",
		"dash", "login", "setpgid", "pgid",
		"sighup", "sigint", "sigquit",
		"sitout-eio",
		"ioctl", "ioctl-void", "ioctl-int", "ioctl-intp", "ioctl-bin", "ioctl-string",
		"fs-append", "fs-compr", "fs-dirsync", "fs-immutable", "fs-journal-data",
		"fs-nodump", "fs-notail", "fs-secrm", "fs-sync", "fs-topdir", "fs-unrm",
		"ext2-append", "ext3-append", "compr", "nodump", "notail", "journal-data",
		"shut-down",
		"lockfile", "waitlock",
		"cloexec",
		"unix-tightsocklen", "tightsocklen",
	} {
		if !strings.Contains(help, "    "+name+" ") {
			t.Errorf("honored option %q is missing from -hhh", name)
		}
	}
	if strings.Contains(help, "    dsusp ") || strings.Contains(help, "    vdsusp ") {
		t.Error("HP-UX dsusp/vdsusp must not be advertised")
	}
	for _, name := range []string{"ip-recverr", "recverr", "iprecverr", "ipv6-recverr", "ipv6-multicast-hops",
		"nopush", "noopt", "tcp-nopush", "tcp-noopt"} {
		if strings.Contains(help, "    "+name+" ") {
			t.Errorf("rejected or unknown option %q must not be advertised in -hhh", name)
		}
	}
	for _, addr := range []string{
		"VSOCK-CONNECT:<cid>:<port>",
		"VSOCK-LISTEN:<port>",
		"UDPLITE4-LISTEN:<port>",
		"UDPLITE4:<host>:<port>",
		"UDPLITE4-SENDTO:<host>:<port>",
		"UDPLITE4-DATAGRAM:<host>:<port>",
		"UDPLITE4-RECV:<port>",
		"UDPLITE4-RECVFROM:<port>",
		"ACCEPT-FD:<fdnum>",
		"ACCEPT:<fdnum>",
	} {
		if !strings.Contains(help, addr) {
			t.Errorf("help missing %q", addr)
		}
	}
}

func TestLinuxHHHIncludesClassicOptionMetadata(t *testing.T) {
	var b bytes.Buffer
	if err := printHelp(&b, 3); err != nil {
		t.Fatal(err)
	}
	help := b.String()
	for name, fields := range map[string][]string{
		"ip-add-source-membership": {"groups=IP4,IP6", "phase=PASTSOCKET", "type=IP-MREQ-SOURCE"},
		"udplite-recv-cscov":       {"groups=UDPLITE", "phase=FD", "type=INT"},
		"ioctl-string":             {"groups=FD", "phase=FD", "type=INT:STRING"},
		"lockfile":                 {"groups=APPL", "phase=INIT", "type=STRING"},
		"dash":                     {"groups=EXEC", "phase=PREEXEC", "type=BOOL"},
		"setpgid":                  {"groups=FORK", "phase=LATE", "type=INT"},
		"sighup":                   {"groups=PARENT", "phase=LATE", "type=CONST"},
		"cloexec":                  {"groups=FD", "phase=LATE", "type=BOOL"},
	} {
		var line string
		for _, candidate := range strings.Split(help, "\n") {
			if strings.HasPrefix(candidate, "    "+name+" ") {
				line = candidate
				break
			}
		}
		if line == "" {
			t.Errorf("-hhh missing %q", name)
			continue
		}
		for _, field := range fields {
			if !strings.Contains(line, field) {
				t.Errorf("%s line %q missing %q", name, line, field)
			}
		}
	}
}

func TestLinuxHelpListsEveryClassicTermiosSpelling(t *testing.T) {
	advertised := advertisedHelpNames(true)
	var missing []string
	for spelling, entry := range classiccatalog.Options {
		isTermios := false
		for _, group := range entry.Groups {
			if group == "TERMIOS" {
				isTermios = true
				break
			}
		}
		if isTermios {
			if _, ok := advertised[spelling]; !ok {
				missing = append(missing, spelling)
			}
		}
	}
	sort.Strings(missing)
	if len(missing) > 0 {
		t.Fatalf("Linux -hhh is missing classic TERMIOS spellings: %s", strings.Join(missing, ", "))
	}
}

func TestLinuxVersionDefinesVSOCK(t *testing.T) {
	var b bytes.Buffer
	if err := printVersion(&b); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(b.String(), "#define WITH_VSOCK 1") {
		t.Fatalf("missing WITH_VSOCK 1:\n%s", b.String())
	}
}
