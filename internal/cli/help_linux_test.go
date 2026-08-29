//go:build linux

package cli

import (
	"bytes"
	"strings"
	"testing"

	"github.com/oittaa/socat/internal/xio"
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
		"ip-retopts", "retopts", "ipretopts",
		"ip-router-alert", "iprouteralert", "routeralert",
		"ipv6-recvdstopts", "recvdstopts",
		"ipv6-recvhopopts", "recvhopopts",
		"ipv6-recvrthdr", "recvrthdr",
		"ipv6-recvpathmtu",
		"setsockopt", "setsockopt-int", "setsockopt-bin", "setsockopt-string",
		"setsockopt-listen", "setsockopt-socket", "setsockopt-connected",
		"sockopt", "sockopt-int", "sockopt-bin", "sockopt-string",
		"sockopt-listen", "sockopt-sock", "sockopt-conn",
		"broadcast", "so-broadcast",
		"vintr", "intr", "veol2", "vswtc", "swtch", "sane", "pendin", "iuclc", "nl1", "crtscts",
		"b7200", "nldly", "crdly", "tabdly", "bsdly", "vtdly", "ffdly", "csize", "xtabs",
		"echoprt", "prterase", "flusho", "termios-setflags", "setflags", "termios-rawer",
		"so-debug", "debug", "so-dontroute", "dontroute", "so-oobinline", "oobinline",
		"so-rcvlowat", "rcvlowat",
		"so-priority", "priority", "so-passcred", "passcred",
		"so-no-check", "no-check", "nocheck",
		"so-detach-filter", "detach-filter", "detachfilter",
		"fiosetown", "siocspgrp",
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
		"sctp-nodelay", "sctp-maxseg",
		"dash", "login", "setpgid", "pgid",
		"sighup", "sigint", "sigquit",
		"sitout-eio",
		"ip-hdrincl", "hdrincl", "iphdrincl",
		"ioctl", "ioctl-void", "ioctl-int", "ioctl-intp", "ioctl-bin", "ioctl-string",
		"fs-append", "fs-compr", "fs-dirsync", "fs-immutable", "fs-journal-data",
		"fs-nodump", "fs-notail", "fs-secrm", "fs-sync", "fs-topdir", "fs-unrm",
		"ext2-append", "ext3-append", "compr", "nodump", "notail", "journal-data",
		"shut-down",
		"lockfile", "waitlock",
		"cloexec",
		"unix-tightsocklen", "tightsocklen",
		"ai-addrconfig", "addrconfig", "ai-passive", "passive", "ai-v4mapped", "v4mapped", "ai-all",
		"res-nsaddr", "dns", "nameserver", "nsaddr", "res-usevc", "usevc",
	} {
		if !strings.Contains(help, "    "+name+" ") {
			t.Errorf("honored option %q is missing from -hhh", name)
		}
	}
	if strings.Contains(help, "    dsusp ") || strings.Contains(help, "    vdsusp ") {
		t.Error("HP-UX dsusp/vdsusp must not be advertised")
	}
	for _, name := range []string{"ip-recverr", "recverr", "iprecverr", "ipv6-recverr", "ipv6-multicast-hops",
		"ip-recvdstaddr", "ip-recvif", "recvdstaddr", "iprecvdstaddr", "recvif",
		"nopush", "noopt", "tcp-nopush", "tcp-noopt",
		"so-sndlowat", "sndlowat",
		"ccid", "dccp-set-ccid",
		"ip-mtu", "ipmtu", "mtu",
		"ip-pktoptions", "ippktoptions", "pktoptions", "pktopts",
		"so-error", "error", "so-acceptconn", "acceptconn",
		"so-peercred", "peercred",
		"so-attach-filter", "attach-filter", "attachfilter",
		"so-security-authentication", "security-authentication", "securityauthentication",
		"so-security-encryption-network", "security-encryption-network", "securityencryptionnetwork",
		"so-security-encryption-transport", "security-encryption-transport", "securityencryptiontransport",
		"res-debug", "res-defnames", "defnames", "res-dnsrch", "dnsrch",
		"res-igntc", "igntc", "res-recurse", "recurse", "res-stayopen", "stayopen",
		"res-retrans", "res-maxretrans", "retrans", "res-retry", "res-maxretry",
		"recvpathmtu",
		"cool-write", "coolwrite", "udp-ignore-peerport", "so-bsdcompat", "bsdcompat",
		"ipv6-authhdr", "authhdr", "ipv6-dstopts", "dstopts",
		"ipv6-hoplimit", "hoplimit", "ipv6-hopopts", "hopopts",
		"ipv6-pktinfo", "ipv6-rthdr", "rthdr",
		"tcp-info", "info", "tcp-md5sig", "md5sig",
		"chroot", "chroot-early",
		"setgid", "setgid-early", "setuid", "setuid-early",
		"substuser", "su", "substuser-delayed", "su-d", "substuser-early", "su-e"} {
		if strings.Contains(help, "    "+name+" ") {
			t.Errorf("rejected or unknown option %q must not be advertised in -hhh", name)
		}
	}
	for _, addr := range []string{
		"VSOCK-CONNECT:<cid>:<port>",
		"VSOCK-LISTEN:<port>",
		"ACCEPT-FD:<fdnum>",
		"ACCEPT:<fdnum>",
	} {
		if !strings.Contains(help, addr) {
			t.Errorf("help missing %q", addr)
		}
	}
}

func TestLinuxHelpOmitsInternalOptionMetadata(t *testing.T) {
	var b bytes.Buffer
	if err := printHelp(&b, 3); err != nil {
		t.Fatal(err)
	}
	help := b.String()
	for _, name := range []string{
		"ip-add-source-membership",
		"ip-hdrincl",
		"ioctl-string",
		"lockfile",
		"dash",
		"setpgid",
		"sighup",
		"cloexec",
		"fiosetown",
		"siocspgrp",
		"so-detach-filter",
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
		for _, field := range []string{"groups=", "phase=", "type="} {
			if strings.Contains(line, field) {
				t.Errorf("%s line %q still contains %q", name, line, field)
			}
		}
	}
}

func TestLinuxHelpListsEveryRegisteredTermiosSpelling(t *testing.T) {
	var b bytes.Buffer
	if err := printHelp(&b, 3); err != nil {
		t.Fatal(err)
	}
	advertised := helpLineNames(b.String())
	var missing []string
	for _, name := range xio.TermiosHelpNames() {
		if !advertised[name] {
			missing = append(missing, name)
		}
	}
	if len(missing) > 0 {
		t.Fatalf("linux -hhh missing registered TERMIOS spellings: %s", strings.Join(missing, ", "))
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
