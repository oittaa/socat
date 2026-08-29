package parse

import (
	"testing"

	"github.com/oittaa/socat/internal/classiccatalog"
)

func TestImplementedOpenFlagAndLockAliasesParse(t *testing.T) {
	tests := []struct {
		spec string
		opt  string
	}{
		{spec: "OPEN:file,o-rdonly", opt: "rdonly"},
		{spec: "OPEN:file,o_rdonly", opt: "rdonly"},
		{spec: "OPEN:file,o-wronly", opt: "wronly"},
		{spec: "OPEN:file,o_wronly", opt: "wronly"},
		{spec: "OPEN:file,o-rdwr", opt: "rdwr"},
		{spec: "OPEN:file,o_rdwr", opt: "rdwr"},
		{spec: "OPEN:file,o-creat", opt: "creat"},
		{spec: "OPEN:file,o-create", opt: "creat"},
		{spec: "OPEN:file,o_creat", opt: "creat"},
		{spec: "OPEN:file,o_create", opt: "creat"},
		{spec: "OPEN:file,create", opt: "creat"},
		{spec: "OPEN:file,o-excl", opt: "excl"},
		{spec: "OPEN:file,o_excl", opt: "excl"},
		{spec: "OPEN:file,o-trunc", opt: "trunc"},
		{spec: "OPEN:file,o-ndelay", opt: "nonblock"},
		{spec: "OPEN:file,o_ndelay", opt: "nonblock"},
		{spec: "OPEN:file,ndelay", opt: "nonblock"},
		{spec: "OPEN:file,f-setlk", opt: "setlk"},
		{spec: "OPEN:file,setlk-wr", opt: "setlk"},
		{spec: "OPEN:file,f-setlkw", opt: "setlkw"},
		{spec: "OPEN:file,setlkw-wr", opt: "setlkw"},
		{spec: "OPEN:file,lock", opt: "setlkw"},
		{spec: "OPEN:file,lockw", opt: "setlkw"},
		{spec: "OPEN:file,new", opt: "unlink-early"},
		{spec: "TCP:127.0.0.1:9,bytes=4", opt: "readbytes"},
		{spec: "TCP:127.0.0.1:9,crlf", opt: "crnl"},
		{spec: "TCP:127.0.0.1:9,close", opt: "end-close"},
		{spec: "SYSTEM:pwd,cd=/tmp", opt: "chdir"},
		{spec: "EXEC:true,sid", opt: "setsid"},
		{spec: "EXEC:true,login", opt: "dash"},
		{spec: "SHELL:true,pgid=0", opt: "setpgid"},
		{spec: "TCP-LISTEN:1,fork,maxchildren=2", opt: "max-children"},
		{spec: "TCP:127.0.0.1:9,intervall=1", opt: "interval"},
		{spec: "TCP6-LISTEN:1,ipv6only", opt: "ipv6-v6only"},
		{spec: "TCP6-LISTEN:1,v6only", opt: "ipv6-v6only"},
		{spec: "PTY,termios-cfmakeraw", opt: "cfmakeraw"},
		{spec: "PTY,raw", opt: "raw"},
		{spec: "PTY,termios-rawer", opt: "rawer"},
		{spec: "PTY,crterase", opt: "echoe"},
		{spec: "PTY,crtkill", opt: "echoke"},
		{spec: "PTY,ctlecho", opt: "echoctl"},
		{spec: "PTY,hup", opt: "hupcl"},
		{spec: "PTY,tandem", opt: "ixoff"},
		{spec: "PTY,pty-intervall=0.2", opt: "pty-interval"},
		{spec: "TUN,tun-no-pi", opt: "iff-no-pi"},
		{spec: "TUN,multicast", opt: "iff-multicast"},
		{spec: "TUN,notrailers", opt: "iff-notrailers"},
		{spec: "TUN,master", opt: "iff-master"},
		{spec: "TUN,slave", opt: "iff-slave"},
		{spec: "TUN,portsel", opt: "iff-portsel"},
		{spec: "TUN,automedia", opt: "iff-automedia"},
		{spec: "PROXY:127.0.0.1:h:80,proxy-auth=u:p", opt: "proxy-authorization"},
		{spec: "PROXY:127.0.0.1:h:80,resolv=0", opt: "proxy-resolve"},
		{spec: "TCP:127.0.0.1:9,priority=6", opt: "so-priority"},
		{spec: "TCP:127.0.0.1:9,passcred", opt: "so-passcred"},
		{spec: "UDP:127.0.0.1:9,nocheck", opt: "so-no-check"},
		{spec: "UDP:127.0.0.1:9,no-check=1", opt: "so-no-check"},
		{spec: "TCP:127.0.0.1:9,rcvlowat=64", opt: "so-rcvlowat"},
		{spec: "UDP:127.0.0.1:9,sndlowat", opt: "so-sndlowat"},
		{spec: "IP4-SENDTO:127.0.0.1:255,hdrincl", opt: "ip-hdrincl"},
		{spec: "IP4-SENDTO:127.0.0.1:255,iphdrincl=1", opt: "ip-hdrincl"},
	}
	for _, tc := range tests {
		t.Run(tc.spec, func(t *testing.T) {
			s, err := ParseSpec(tc.spec)
			if err != nil {
				t.Fatal(err)
			}
			if !s.HasOption(tc.opt) {
				t.Fatalf("HasOption(%q) false; options=%v", tc.opt, s.Options)
			}
			if s.Options[len(s.Options)-1].Name != tc.opt {
				t.Fatalf("stored Name=%q want %q", s.Options[len(s.Options)-1].Name, tc.opt)
			}
		})
	}
}

func TestCatalogOpenFlagAliasesShareClassicGroups(t *testing.T) {
	pairs := [][2]string{
		{"o-rdonly", "rdonly"},
		{"o-wronly", "wronly"},
		{"o-rdwr", "rdwr"},
		{"o-creat", "creat"},
		{"o-excl", "excl"},
		{"o-trunc", "trunc"},
		{"o-ndelay", "nonblock"},
		{"ndelay", "nonblock"},
		{"f-setlk", "setlk"},
		{"lock", "setlkw"},
		{"new", "unlink-early"},
		{"bytes", "readbytes"},
		{"crlf", "crnl"},
		{"close", "end-close"},
		{"cd", "chdir"},
		{"sid", "setsid"},
		{"login", "dash"},
		{"pgid", "setpgid"},
		{"crterase", "echoe"},
		{"termios-cfmakeraw", "cfmakeraw"},
		{"tun-no-pi", "iff-no-pi"},
		{"multicast", "iff-multicast"},
		{"notrailers", "iff-notrailers"},
		{"master", "iff-master"},
		{"slave", "iff-slave"},
		{"portsel", "iff-portsel"},
		{"automedia", "iff-automedia"},
		{"proxy-auth", "proxy-authorization"},
		{"priority", "so-priority"},
		{"passcred", "so-passcred"},
		{"nocheck", "so-no-check"},
		{"no-check", "so-no-check"},
		{"rcvlowat", "so-rcvlowat"},
		{"sndlowat", "so-sndlowat"},
	}
	for _, pair := range pairs {
		alias, canon := pair[0], pair[1]
		if CanonicalOptionName(alias) != canon {
			t.Errorf("CanonicalOptionName(%q)=%q want %q", alias, CanonicalOptionName(alias), canon)
		}
		se, sok := classiccatalog.Lookup(alias)
		ce, cok := classiccatalog.Lookup(canon)
		if !sok || !cok {
			t.Errorf("catalog lookup %q ok=%v %q ok=%v", alias, sok, canon, cok)
			continue
		}
		if se.Phase != ce.Phase {
			t.Errorf("%s/%s phase %q vs %q", alias, canon, se.Phase, ce.Phase)
		}
	}
}

func TestRawRemainsDistinctFromCFMakeRaw(t *testing.T) {
	if got := CanonicalOptionName("raw"); got != "raw" {
		t.Fatalf("CanonicalOptionName(raw)=%q want raw", got)
	}
	if got := CanonicalOptionName("termios-cfmakeraw"); got != "cfmakeraw" {
		t.Fatalf("CanonicalOptionName(termios-cfmakeraw)=%q want cfmakeraw", got)
	}
}
