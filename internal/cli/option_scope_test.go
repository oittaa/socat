package cli

import (
	"reflect"
	"strings"
	"testing"

	"github.com/oittaa/socat/internal/xio"
)

func TestAddressAllowsOption(t *testing.T) {
	cases := []struct {
		addr, opt string
		want      bool
	}{
		{"TCP-CONNECT", "readbytes", true},
		{"TCP-CONNECT", "crnl", true},
		{"TCP-CONNECT", "cr", true},
		{"TCP-CONNECT", "shut-down", true},
		{"TCP-CONNECT", "setsid", true},
		{"TCP-CONNECT", "pty", false},
		{"TCP-CONNECT", "echo", false},
		{"TCP-CONNECT", "excl", false},
		{"TCP-CONNECT", "append", true},
		{"TCP-CONNECT", "ftruncate", false},
		{"FD", "ftruncate", true},
		{"FD", "append", true},
		{"EXEC", "append", true},
		{"STDIO", "append", true},
		{"TCP-CONNECT", "fork", true},
		{"UDP-CONNECT", "fork", false},
		{"UDP-CONNECT", "lowport", true},
		{"UDP-LISTEN", "accept-timeout", true},
		{"UDP-RECVFROM", "accept-timeout", false},
		{"UDP-RECVFROM", "range", true},
		{"UNIX-RECVFROM", "range", false},
		{"UNIX-RECVFROM", "accept-timeout", false},
		{"CREATE", "excl", false},
		{"OPEN", "excl", true},
		{"EXEC", "pty", true},
		{"EXEC", "fork", false},
		{"EXEC", "dash", true},
		{"EXEC", "setpgid", true},
		{"SHELL", "dash", true},
		{"SYSTEM", "pgid", true},
		{"TCP-CONNECT", "dash", false},
		{"TCP-CONNECT", "setpgid", false},
		{"EXEC", "sighup", true},
		{"SYSTEM", "sigint", true},
		{"SHELL", "sigquit", true},
		{"TCP-CONNECT", "sighup", false},
		{"OPEN", "sigint", false},
		{"TCP-LISTEN", "sourceport", true},
		{"OPEN", "sourceport", false},
		{"TUN", "rcvtimeo", false},
		{"INTERFACE", "rcvtimeo", true},
		{"OPENSSL", "cert", true},
		{"TCP-CONNECT", "cert", false},
		{"QUIC", "lowport", true},
		{"WS", "nodelay", true},
		{"TCP", "noatime", true},
		{"UDP4", "pktinfo", true},
		{"OPEN", "noatime", true},
		{"CREATE", "pktinfo", false},
		{"OPEN", "o-direct", true},
		{"PIPE", "o-direct", true},
		{"CREATE", "o-direct", false},
		{"OPEN", "o-sync", true},
		{"PIPE", "o-sync", true},
		{"CREATE", "o-sync", false},
		{"FD", "o-sync", false},
		{"OPEN", "async", true},
		{"FD", "async", true},
		{"TCP-CONNECT", "async", true},
		{"CREATE", "async", true},
		{"OPEN", "lseek", true},
		{"FD", "lseek", true},
		{"TCP-CONNECT", "lseek", false},
		{"PIPE", "lseek", false},
		{"FD", "flock", true},
		{"TCP-CONNECT", "flock", true},
		{"OPEN", "flock", true},
		{"FD", "perm-late", true},
		{"OPEN", "perm-late", true},
		{"TCP-CONNECT", "perm-late", true},
		{"OPEN", "fs-noatime", true},
		{"CREATE", "fs-noatime", true},
		{"FD", "fs-noatime", true},
		{"PIPE", "fs-noatime", false},
		{"EXEC", "fs-noatime", false},
		{"OPEN", "fs-append", true},
		{"CREATE", "fs-append", true},
		{"FD", "fs-append", true},
		{"PIPE", "fs-append", false},
		{"EXEC", "fs-append", false},
		{"TCP", "fs-append", false},
		{"OPEN", "nodump", true},
		{"TCP", "nodump", false},
		{"PIPE", "ext2-nodump", false},
		{"OPEN", "notail", true},
		{"EXEC", "fs-immutable", false},
		{"UDP4", "ipv6-join-group", false},
		{"UDP4-RECV", "ipv6-join-group", false},
		{"TCP4", "ipv6-join-group", false},
		{"IP4", "ipv6-join-group", false},
		{"UDP6", "ipv6-join-group", true},
		{"UDP6-RECV", "ipv6-join-group", true},
		{"TCP6", "ipv6-join-group", true},
		{"UDP4", "ip-add-membership", true},
		{"UDP6", "ip-add-membership", true},
		{"UDP4", "join-group", false},
		{"UDP6", "join-group", true},
		{"UDP4", "add-membership", true},
		{"UDP4", "membership", true},
		{"UDP4", "ipv6-multicast-loop", false},
		{"UDP6", "ipv6-multicast-loop", true},
		{"TCP4", "mcloop6", false},
		{"TCP6", "mcloop6", true},
		{"UDP4", "ipv6-join-source-group", false},
		{"UDP6", "ipv6-join-source-group", true},
		{"UDP4", "join-source-group", false},
		{"UDP6", "join-source-group", true},
		{"UDP4", "ip-add-source-membership", true},
		{"UDP6", "ip-add-source-membership", true},
		{"UDP4", "ip-multicast-ttl", true},
		{"TCP", "ip-freebind", true},
		{"TCP", "ip-transparent", true},
		{"ACCEPT-FD", "fork", true},
		{"ACCEPT-FD", "range", true},
		{"ACCEPT-FD", "sourceport", true},
		{"ACCEPT-FD", "lowport", true},
		{"ACCEPT-FD", "tcpwrap", true},
		{"ACCEPT-FD", "backlog", false},
		{"ACCEPT-FD", "accept-timeout", false},
		{"ACCEPT-FD", "pty", false},
		{"ACCEPT-FD", "unlink-early", false},
		{"ACCEPT", "fork", true},
		{"ACCEPT", "excl", false},
		{"TCP-CONNECT", "group-early", false},
		{"OPEN", "group-early", true},
		{"CREATE", "group-early", true},
		{"TCP-CONNECT", "gid-e", false},
		{"TCP-CONNECT", "group-late", true},
		{"TCP-CONNECT", "chdir", true},
		{"TCP-CONNECT", "umask", true},
		{"OPENSSL-L", "cert", true},
		{"SSL-CONNECT", "cert", true},
		{"SSL-LISTEN", "cert", true},
		{"ABSTRACT-L", "backlog", true},
		{"UNIX-LISTEN", "backlog", true},
		{"TLS-LISTEN", "backlog", true},
		{"WS-LISTEN", "backlog", true},
		{"WSS-LISTEN", "backlog", true},
		{"UDP-LISTEN", "backlog", true},
		{"UNIX-DATAGRAM", "unlink-early", true},
		{"SOCKET-SENDTO", "range", false},
		{"SOCKET-DATAGRAM", "range", true},
		{"SOCKET-RECV", "range", true},
		{"SOCKET-RECVFROM", "range", true},
		{"SOCKET-RECVFROM", "fork", true},
		{"SOCKET-RECV", "fork", false},
	}
	for _, tc := range cases {
		got := optionAllowedOnAddress(tc.addr, tc.opt)
		if got != tc.want {
			t.Errorf("optionAllowedOnAddress(%s, %s)=%v want %v", tc.addr, tc.opt, got, tc.want)
		}
	}
}

func TestOptionCapsAliasInheritance(t *testing.T) {
	for _, group := range helpOptionGroups() {
		for _, option := range group.opts {
			canon, ok := supportedAddressOptions[strings.ToLower(option.name)]
			if !ok {
				t.Errorf("canonical %q missing from supportedAddressOptions", option.name)
				continue
			}
			for _, alias := range option.aliases {
				got, ok := supportedAddressOptions[strings.ToLower(alias)]
				if !ok {
					t.Errorf("%s alias %q missing from supportedAddressOptions", option.name, alias)
					continue
				}
				if !reflect.DeepEqual(got.optionCaps, canon.optionCaps) {
					t.Errorf("%s alias %s caps=%v want canonical %v", option.name, alias, got.optionCaps, canon.optionCaps)
				}
			}
		}
	}

	join := supportedAddressOptions["ipv6-join-group"].optionCaps
	if got := supportedAddressOptions["join-group"].optionCaps; !reflect.DeepEqual(got, join) {
		t.Fatalf("join-group caps=%v want ipv6-join-group %v", got, join)
	}
	member := supportedAddressOptions["ip-add-membership"].optionCaps
	if reflect.DeepEqual(join, member) {
		t.Fatalf("ipv6-join-group and ip-add-membership must keep distinct caps: %v", join)
	}
	if !reflect.DeepEqual(join, capIP6) {
		t.Fatalf("ipv6-join-group caps=%v want %v", join, capIP6)
	}
	if !reflect.DeepEqual(member, capIP4IP6) {
		t.Fatalf("ip-add-membership caps=%v want %v", member, capIP4IP6)
	}

	srcJoin := supportedAddressOptions["ipv6-join-source-group"].optionCaps
	srcMember := supportedAddressOptions["ip-add-source-membership"].optionCaps
	if reflect.DeepEqual(srcJoin, srcMember) {
		t.Fatalf("ipv6-join-source-group and ip-add-source-membership must keep distinct caps: %v", srcJoin)
	}
	if !reflect.DeepEqual(srcJoin, capIP6) {
		t.Fatalf("ipv6-join-source-group caps=%v want %v", srcJoin, capIP6)
	}
	if !reflect.DeepEqual(srcMember, capIP4IP6) {
		t.Fatalf("ip-add-source-membership caps=%v want %v", srcMember, capIP4IP6)
	}
}

func TestAdvertisedOptionsHaveDeliberateScope(t *testing.T) {
	var missing []string
	for _, group := range helpOptionGroups() {
		sectionGroups := optionAddressGroups(group.title)
		for _, option := range group.opts {
			if option.unrestricted {
				if len(option.optionCaps) > 0 {
					t.Errorf("%s: unrestricted options must not set optionCaps", option.name)
				}
				continue
			}
			if len(option.optionCaps) > 0 || len(option.addressTypes) > 0 || len(sectionGroups) > 0 {
				continue
			}
			missing = append(missing, option.name)
		}
	}
	if len(missing) > 0 {
		t.Fatalf("advertised options missing scope metadata (optionCaps, unrestricted, addressTypes, or section groups): %v", missing)
	}
	for _, name := range extraHelpNames(true) {
		spec, ok := supportedAddressOptions[strings.ToLower(name)]
		if !ok || !reflect.DeepEqual(spec.optionCaps, capTermios) {
			t.Errorf("extra termios name %q caps=%v ok=%v want termios", name, spec.optionCaps, ok)
		}
	}
	for _, name := range xio.TermiosOptionNames() {
		spec, ok := supportedAddressOptions[strings.ToLower(name)]
		if !ok || !reflect.DeepEqual(spec.optionCaps, capTermios) {
			t.Errorf("recognized termios name %q caps=%v ok=%v want termios", name, spec.optionCaps, ok)
		}
	}
	for name, spec := range supportedAddressOptions {
		for _, cap := range spec.optionCaps {
			switch cap {
			case "ip-dccp", "ip-udplite":
				t.Errorf("%s optionCaps includes unsupported %q", name, cap)
			}
		}
	}
}
