package parse

import "testing"

func TestParseSTDIO(t *testing.T) {
	ch, err := ParseChannel("-")
	if err != nil {
		t.Fatal(err)
	}
	if ch.Single == nil || ch.Single.Type != "STDIO" {
		t.Fatalf("got %+v", ch.Single)
	}
}

func TestParseFD(t *testing.T) {
	ch, err := ParseChannel("2")
	if err != nil {
		t.Fatal(err)
	}
	if ch.Single.Type != "FD" || ch.Single.Params[0] != "2" {
		t.Fatalf("got %+v", ch.Single)
	}
}

func TestParseTCP4(t *testing.T) {
	// Classic test TCP4 uses TCP4-LISTEN and TCP4:host:port
	ch, err := ParseChannel("TCP4-LISTEN:8080,reuseaddr,fork")
	if err != nil {
		t.Fatal(err)
	}
	s := ch.Single
	if s.Type != "TCP4-LISTEN" {
		t.Fatalf("type %q", s.Type)
	}
	if len(s.Params) != 1 || s.Params[0] != "8080" {
		t.Fatalf("params %v", s.Params)
	}
	if !s.BoolOption("reuseaddr") || !s.BoolOption("fork") {
		t.Fatalf("options %v", s.Options)
	}
}

func TestParseTCPConnect(t *testing.T) {
	ch, err := ParseChannel("TCP4:127.0.0.1:8080")
	if err != nil {
		t.Fatal(err)
	}
	s := ch.Single
	if s.Type != "TCP4" || len(s.Params) != 2 {
		t.Fatalf("got %+v", s)
	}
	if s.Params[0] != "127.0.0.1" || s.Params[1] != "8080" {
		t.Fatalf("params %v", s.Params)
	}
}

func TestParseDual(t *testing.T) {
	// Classic DUALSTDIO / stdin!!stdout
	ch, err := ParseChannel("stdin!!stdout")
	if err != nil {
		t.Fatal(err)
	}
	if !ch.IsDual() {
		t.Fatal("expected dual")
	}
	if ch.Dual.Left.Type != "STDIN" || ch.Dual.Right.Type != "STDOUT" {
		t.Fatalf("got left=%+v right=%+v", ch.Dual.Left, ch.Dual.Right)
	}
}

func TestParseDualWithOptions(t *testing.T) {
	ch, err := ParseChannel("TCP4:127.0.0.1:9,connect-timeout=1!!STDOUT")
	if err != nil {
		t.Fatal(err)
	}
	if !ch.IsDual() {
		t.Fatal("expected dual")
	}
	if ch.Dual.Left.Type != "TCP4" {
		t.Fatalf("left type %s", ch.Dual.Left.Type)
	}
	if ch.Dual.Left.OptionValue("connect-timeout", "") != "1" {
		t.Fatalf("options %v", ch.Dual.Left.Options)
	}
}

func TestParseGOPEN(t *testing.T) {
	ch, err := ParseChannel("/tmp/foo")
	if err != nil {
		t.Fatal(err)
	}
	if ch.Single.Type != "GOPEN" || ch.Single.Params[0] != "/tmp/foo" {
		t.Fatalf("got %+v", ch.Single)
	}
}

func TestParseQuotedParam(t *testing.T) {
	ch, err := ParseChannel(`EXEC:"echo hello",pty`)
	if err != nil {
		t.Fatal(err)
	}
	if ch.Single.Type != "EXEC" {
		t.Fatalf("type %s", ch.Single.Type)
	}
	if ch.Single.Params[0] != "echo hello" {
		t.Fatalf("param %q", ch.Single.Params[0])
	}
	if !ch.Single.BoolOption("pty") {
		t.Fatal("missing pty")
	}
}

func TestParseIPv6(t *testing.T) {
	ch, err := ParseChannel("TCP6:[::1]:8080")
	if err != nil {
		t.Fatal(err)
	}
	s := ch.Single
	// [::1] may be one param if we don't split inside brackets
	if s.Type != "TCP6" {
		t.Fatalf("type %s", s.Type)
	}
	if len(s.Params) < 1 {
		t.Fatalf("params %v", s.Params)
	}
	// With bracket protection, host is [::1] and port is 8080
	if len(s.Params) != 2 || s.Params[0] != "[::1]" || s.Params[1] != "8080" {
		t.Fatalf("params %v (want [::1] and 8080)", s.Params)
	}
}

func TestParseOptionValue(t *testing.T) {
	ch, err := ParseChannel("TCP-LISTEN:80,bind=127.0.0.1,backlog=10")
	if err != nil {
		t.Fatal(err)
	}
	if ch.Single.OptionValue("bind", "") != "127.0.0.1" {
		t.Fatal(ch.Single.Options)
	}
	if ch.Single.OptionValue("backlog", "") != "10" {
		t.Fatal(ch.Single.Options)
	}
}

func TestLastOptionWins(t *testing.T) {
	tests := []struct {
		name string
		spec string
		opt  string
		want string
	}{
		{name: "canonical", spec: "CREATE:file,perm=600,perm=644", opt: "perm", want: "644"},
		{name: "alias-last", spec: "TCP-LISTEN:1,reuseaddr=0,so-reuseaddr=1", opt: "reuseaddr", want: "1"},
		{name: "canonical-last", spec: "TCP-LISTEN:1,so-reuseaddr=1,reuseaddr=0", opt: "reuseaddr", want: "0"},
		{name: "sndbuf-alias", spec: "TCP:127.0.0.1:9,so-sndbuf=4096", opt: "sndbuf", want: "4096"},
		{name: "rcvbuf-alias", spec: "TCP:127.0.0.1:9,so-rcvbuf=8192", opt: "rcvbuf", want: "8192"},
		{name: "sndbuf-late-alias", spec: "TCP:127.0.0.1:9,so-sndbuf-late=4096", opt: "sndbuf-late", want: "4096"},
		{name: "rcvbuf-late-alias", spec: "TCP:127.0.0.1:9,so-rcvbuf-late=8192", opt: "rcvbuf-late", want: "8192"},
		{name: "bindtodevice-if", spec: "TCP:127.0.0.1:9,if=lo", opt: "bindtodevice", want: "lo"},
		{name: "bindtodevice-so", spec: "TCP:127.0.0.1:9,so-bindtodevice=eth0", opt: "bindtodevice", want: "eth0"},
		{name: "bindtodevice-interface", spec: "TCP4:127.0.0.1:9,interface=lo", opt: "bindtodevice", want: "lo"},
		{name: "cert-openssl-certificate-last", spec: "TLS:127.0.0.1:443,cert=/tmp/a.pem,openssl-certificate=/tmp/b.pem", opt: "cert", want: "/tmp/b.pem"},
		{name: "openssl-certificate-then-cert", spec: "TLS:127.0.0.1:443,openssl-certificate=/tmp/a.pem,cert=/tmp/b.pem", opt: "cert", want: "/tmp/b.pem"},
		{name: "certificate-alias", spec: "OPENSSL:127.0.0.1:443,certificate=/tmp/c.pem", opt: "cert", want: "/tmp/c.pem"},
		{name: "openssl-key", spec: "TLS:127.0.0.1:443,openssl-key=/tmp/k.pem", opt: "key", want: "/tmp/k.pem"},
		{name: "openssl-cafile-last", spec: "TLS:127.0.0.1:443,cafile=/tmp/ca1.pem,openssl-cafile=/tmp/ca2.pem", opt: "cafile", want: "/tmp/ca2.pem"},
		{name: "ca-then-openssl-cafile", spec: "TLS:127.0.0.1:443,ca=/tmp/ca1.pem,openssl-cafile=/tmp/ca2.pem", opt: "cafile", want: "/tmp/ca2.pem"},
		{name: "cipherlist", spec: "TLS:127.0.0.1:443,cipherlist=ECDHE-ECDSA-AES256-GCM-SHA384", opt: "ciphers", want: "ECDHE-ECDSA-AES256-GCM-SHA384"},
		{name: "cn", spec: "TLS:127.0.0.1:443,cn=localhost", opt: "commonname", want: "localhost"},
		{name: "min-proto-version-last", spec: "TLS:127.0.0.1:443,min-version=TLS1.0,min-proto-version=TLS1.2", opt: "openssl-min-proto-version", want: "TLS1.2"},
		{name: "max-proto-version", spec: "TLS:127.0.0.1:443,max-proto-version=TLS1.3", opt: "openssl-max-proto-version", want: "TLS1.3"},
		{name: "so-debug-alias", spec: "TCP:127.0.0.1:9,debug=1", opt: "so-debug", want: "1"},
		{name: "cork-alias", spec: "TCP:127.0.0.1:9,cork=1", opt: "tcp-cork", want: "1"},
		{name: "tcp-nopush-alias", spec: "TCP:127.0.0.1:9,tcp-nopush=1", opt: "nopush", want: "1"},
		{name: "tcp-noopt-alias", spec: "TCP:127.0.0.1:9,tcp-noopt=1", opt: "noopt", want: "1"},
		{name: "priority-alias", spec: "TCP:127.0.0.1:9,priority=6", opt: "so-priority", want: "6"},
		{name: "passcred-alias", spec: "TCP:127.0.0.1:9,passcred=1", opt: "so-passcred", want: "1"},
		{name: "nocheck-alias", spec: "UDP:127.0.0.1:9,nocheck=1", opt: "so-no-check", want: "1"},
		{name: "no-check-alias", spec: "UDP:127.0.0.1:9,no-check=1", opt: "so-no-check", want: "1"},
		{name: "mss-late-alias", spec: "TCP:127.0.0.1:9,mss-late=512", opt: "tcp-maxseg-late", want: "512"},
		{name: "o-rdonly-then-wronly", spec: "OPEN:file,o-rdonly,o-wronly", opt: "wronly", want: "1"},
		{name: "creat-alias-last", spec: "OPEN:file,creat=0,o-creat=1", opt: "creat", want: "1"},
		{name: "ndelay-then-nonblock-off", spec: "OPEN:file,ndelay,nonblock=0", opt: "nonblock", want: "0"},
		{name: "lock-then-setlkw-off", spec: "OPEN:file,lock,setlkw=0", opt: "setlkw", want: "0"},
		{name: "bytes-alias", spec: "TCP:127.0.0.1:9,bytes=4", opt: "readbytes", want: "4"},
		{name: "crlf-then-crnl-off", spec: "TCP:127.0.0.1:9,crlf,crnl=0", opt: "crnl", want: "0"},
		{name: "cd-alias", spec: "SYSTEM:pwd,cd=/tmp", opt: "chdir", want: "/tmp"},
		{name: "login-alias", spec: "EXEC:true,login", opt: "dash", want: "1"},
		{name: "pgid-alias", spec: "SHELL:true,pgid=0", opt: "setpgid", want: "0"},
		{name: "new-then-unlink-early-off", spec: "OPEN:file,new,unlink-early=0", opt: "unlink-early", want: "0"},
		{name: "close-alias", spec: "TCP:127.0.0.1:9,close", opt: "end-close", want: "1"},
		{name: "maxchildren-alias", spec: "TCP-LISTEN:1,fork,maxchildren=3", opt: "max-children", want: "3"},
		{name: "intervall-alias", spec: "TCP:127.0.0.1:9,retry=1,intervall=2", opt: "interval", want: "2"},
		{name: "v6only-alias", spec: "TCP6-LISTEN:1,v6only=0", opt: "ipv6-v6only", want: "0"},
		{name: "proxy-auth-alias", spec: "PROXY:127.0.0.1:h:80,proxy-auth=u:p", opt: "proxy-authorization", want: "u:p"},
		{name: "resolv-then-resolve-off", spec: "PROXY:127.0.0.1:h:80,resolv,proxy-resolve=0", opt: "proxy-resolve", want: "0"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			s, err := ParseSpec(tc.spec)
			if err != nil {
				t.Fatal(err)
			}
			if got := s.OptionValue(tc.opt, ""); got != tc.want {
				t.Fatalf("%s=%q want %q", tc.opt, got, tc.want)
			}
		})
	}
}

func TestParsePIPE(t *testing.T) {
	ch, err := ParseChannel("PIPE")
	if err != nil {
		t.Fatal(err)
	}
	if ch.Single.Type != "PIPE" || len(ch.Single.Params) != 0 {
		t.Fatalf("got %+v", ch.Single)
	}
}

func TestParseUNIX(t *testing.T) {
	ch, err := ParseChannel("UNIX-LISTEN:/tmp/sock,unlink-early,mode=777")
	if err != nil {
		t.Fatal(err)
	}
	s := ch.Single
	if s.Type != "UNIX-LISTEN" || s.Params[0] != "/tmp/sock" {
		t.Fatalf("got %+v", s)
	}
	if !s.BoolOption("unlink-early") {
		t.Fatal("unlink-early")
	}
	if s.OptionValue("mode", "") != "777" {
		t.Fatal(s.Options)
	}
}

func TestBangInsideQuotesNotDual(t *testing.T) {
	// !! inside quotes should not split dual
	ch, err := ParseChannel(`EXEC:"echo a!!b"`)
	if err != nil {
		t.Fatal(err)
	}
	if ch.IsDual() {
		t.Fatal("should not be dual")
	}
	if ch.Single.Params[0] != "echo a!!b" {
		t.Fatalf("param %q", ch.Single.Params[0])
	}
}

func TestBoolOptionEmptyDisables(t *testing.T) {
	s, err := ParseSpec("TCP4-LISTEN:1,so-reuseaddr=")
	if err != nil {
		t.Fatal(err)
	}
	if !s.HasOption("reuseaddr") {
		t.Fatal("expected HasOption reuseaddr")
	}
	if s.BoolOption("reuseaddr") {
		t.Fatal("so-reuseaddr= must be false")
	}
}

func TestOptionAliases(t *testing.T) {
	s, err := ParseSpec("UDP6-RECV:1,ipv6-join-group=[ff02::2]:lo,bind-tempname=/tmp/x.XXXXXX,so-reuseport")
	if err != nil {
		t.Fatal(err)
	}
	if !s.HasOption("ipv6-join-group") {
		t.Fatal("ipv6-join-group")
	}
	if s.HasOption("ip-add-membership") {
		t.Fatal("ipv6-join-group must not fold onto ip-add-membership")
	}
	if got := s.OptionValue("ipv6-join-group", ""); got != "[ff02::2]:lo" {
		t.Fatalf("membership %q", got)
	}
	aliases, err := ParseSpec("UDP6-RECV:1,join-group=[ff02::2]:lo,add-membership=224.0.0.1:lo,membership=224.0.0.2:eth0,ipv6-add-membership=[ff02::3]:eth1,ip-membership=224.0.0.3:lo")
	if err != nil {
		t.Fatal(err)
	}
	if aliases.Options[0].Name != "ipv6-join-group" || aliases.Options[0].Spelling != "join-group" {
		t.Fatalf("join-group stored as %+v", aliases.Options[0])
	}
	if aliases.Options[1].Name != "ip-add-membership" || aliases.Options[1].Spelling != "add-membership" {
		t.Fatalf("add-membership stored as %+v", aliases.Options[1])
	}
	if aliases.Options[2].Name != "ip-add-membership" || aliases.Options[2].Spelling != "membership" {
		t.Fatalf("membership stored as %+v", aliases.Options[2])
	}
	if aliases.Options[3].Name != "ipv6-join-group" || aliases.Options[3].Spelling != "ipv6-add-membership" {
		t.Fatalf("ipv6-add-membership stored as %+v", aliases.Options[3])
	}
	if aliases.Options[4].Name != "ip-add-membership" || aliases.Options[4].Spelling != "ip-membership" {
		t.Fatalf("ip-membership stored as %+v", aliases.Options[4])
	}
	if !aliases.HasOption("ipv6-join-group") {
		t.Fatal("join-group must fold onto ipv6-join-group")
	}
	if !aliases.HasOption("ip-add-membership") {
		t.Fatal("add-membership must fold onto ip-add-membership")
	}
	if CanonicalOptionName("join-group") != "ipv6-join-group" || CanonicalOptionName("ipv6-join-group") != "ipv6-join-group" {
		t.Fatalf("join-group fold=%q ipv6-join-group fold=%q", CanonicalOptionName("join-group"), CanonicalOptionName("ipv6-join-group"))
	}
	if CanonicalOptionName("mcloop") != "ip-multicast-loop" || CanonicalOptionName("mcloop6") != "ipv6-multicast-loop" {
		t.Fatalf("mcloop=%q mcloop6=%q", CanonicalOptionName("mcloop"), CanonicalOptionName("mcloop6"))
	}
	if CanonicalOptionName("source-membership") != "ip-add-source-membership" {
		t.Fatalf("source-membership=%q", CanonicalOptionName("source-membership"))
	}
	if CanonicalOptionName("join-source-group") != "ipv6-join-source-group" || CanonicalOptionName("ipv6-join-source-group") != "ipv6-join-source-group" {
		t.Fatalf("join-source-group must not fold onto ip-add-source-membership: %q", CanonicalOptionName("join-source-group"))
	}
	if CanonicalOptionName("recverr") != "ip-recverr" || CanonicalOptionName("ipv6-recverr") != "ipv6-recverr" {
		t.Fatalf("recverr=%q ipv6-recverr=%q", CanonicalOptionName("recverr"), CanonicalOptionName("ipv6-recverr"))
	}
	if !s.HasOption("unix-bind-tempname") || !s.HasOption("bind-tempname") {
		t.Fatal("bind-tempname alias")
	}
	if !s.BoolOption("reuseport") || !s.BoolOption("so-reuseport") {
		t.Fatal("so-reuseport alias")
	}
}

func TestUnlinkDeleteRemoveAliases(t *testing.T) {
	for _, spec := range []string{"OPEN:file,unlink", "OPEN:file,delete", "OPEN:file,remove"} {
		s, err := ParseSpec(spec)
		if err != nil {
			t.Fatal(err)
		}
		if !s.BoolOption("unlink") {
			t.Fatalf("%s: unlink not set (options=%v)", spec, s.Options)
		}
	}
}

func TestUserEarlyGroupEarlyAliases(t *testing.T) {
	s, err := ParseSpec("OPEN:file,uid-e=1000,gid-e=100")
	if err != nil {
		t.Fatal(err)
	}
	if got := s.OptionValue("user-early", ""); got != "1000" {
		t.Fatalf("user-early=%q want 1000 (options=%v)", got, s.Options)
	}
	if got := s.OptionValue("uid-e", ""); got != "1000" {
		t.Fatalf("uid-e lookup=%q want 1000", got)
	}
	if got := s.OptionValue("group-early", ""); got != "100" {
		t.Fatalf("group-early=%q want 100", got)
	}
	if got := s.OptionValue("gid-e", ""); got != "100" {
		t.Fatalf("gid-e lookup=%q want 100", got)
	}
	if len(s.Options) != 2 || s.Options[0].Name != "user-early" || s.Options[1].Name != "group-early" {
		t.Fatalf("stored names=%v want user-early, group-early", s.Options)
	}
}

func TestClassicCompatibilityOptionAliases(t *testing.T) {
	s, err := ParseSpec("OPENSSL:localhost:443,cipher=ECDHE-ECDSA-AES256-GCM-SHA384,sockopt-listen=1:2:1,f-setlk-wr")
	if err != nil {
		t.Fatal(err)
	}
	if got := s.OptionValue("ciphers", ""); got != "ECDHE-ECDSA-AES256-GCM-SHA384" {
		t.Fatalf("ciphers=%q", got)
	}
	if got := s.OptionValue("setsockopt-listen", ""); got != "1:2:1" {
		t.Fatalf("setsockopt-listen=%q", got)
	}
	if !s.BoolOption("setlk") {
		t.Fatal("f-setlk-wr alias did not normalize to setlk")
	}
}

func TestGenericSetsockoptAliases(t *testing.T) {
	s, err := ParseSpec("TCP:localhost:1,sockopt=1:9:1,sockopt-int=1:9:1,sockopt-bin=1:9:x01,sockopt-string=1:1:lo,sockopt-sock=1:9:1,sockopt-conn=1:9:1")
	if err != nil {
		t.Fatal(err)
	}
	if got := s.OptionValue("setsockopt", ""); got != "1:9:1" {
		t.Fatalf("setsockopt=%q", got)
	}
	if got := s.OptionValue("setsockopt-int", ""); got != "1:9:1" {
		t.Fatalf("setsockopt-int=%q", got)
	}
	if got := s.OptionValue("setsockopt-bin", ""); got != "1:9:x01" {
		t.Fatalf("setsockopt-bin=%q", got)
	}
	if got := s.OptionValue("setsockopt-string", ""); got != "1:1:lo" {
		t.Fatalf("setsockopt-string=%q", got)
	}
	if got := s.OptionValue("setsockopt-socket", ""); got != "1:9:1" {
		t.Fatalf("setsockopt-socket=%q", got)
	}
	if got := s.OptionValue("setsockopt-connected", ""); got != "1:9:1" {
		t.Fatalf("setsockopt-connected=%q", got)
	}
}

func TestIoctlAliasFoldsToIoctlVoid(t *testing.T) {
	s, err := ParseSpec("FD:3,ioctl=0x541B")
	if err != nil {
		t.Fatal(err)
	}
	if got := s.OptionValue("ioctl-void", ""); got != "0x541B" {
		t.Fatalf("ioctl-void=%q", got)
	}
	if CanonicalOptionName("ioctl") != "ioctl-void" {
		t.Fatalf("CanonicalOptionName(ioctl)=%q", CanonicalOptionName("ioctl"))
	}
}

func TestDirectAndFSNoatimeAliases(t *testing.T) {
	s, err := ParseSpec("OPEN:file,direct")
	if err != nil {
		t.Fatal(err)
	}
	if !s.BoolOption("o-direct") {
		t.Fatal("direct alias did not normalize to o-direct")
	}
	s, err = ParseSpec("OPEN:file,o_direct")
	if err != nil {
		t.Fatal(err)
	}
	if !s.BoolOption("o-direct") {
		t.Fatal("o_direct alias did not normalize to o-direct")
	}
	s, err = ParseSpec("OPEN:file,o-direct=0")
	if err != nil {
		t.Fatal(err)
	}
	if s.BoolOption("o-direct") {
		t.Fatal("o-direct=0 must be false")
	}
	s, err = ParseSpec("OPEN:file,ext2-noatime")
	if err != nil {
		t.Fatal(err)
	}
	if !s.BoolOption("fs-noatime") {
		t.Fatal("ext2-noatime alias did not normalize to fs-noatime")
	}
	s, err = ParseSpec("OPEN:file,ext3-noatime")
	if err != nil {
		t.Fatal(err)
	}
	if !s.BoolOption("fs-noatime") {
		t.Fatal("ext3-noatime alias did not normalize to fs-noatime")
	}
	s, err = ParseSpec("OPEN:file,noatime")
	if err != nil {
		t.Fatal(err)
	}
	if s.BoolOption("fs-noatime") {
		t.Fatal("noatime must not alias fs-noatime")
	}
	if CanonicalOptionName("noatime") != "noatime" {
		t.Fatalf("noatime canonicalized to %q", CanonicalOptionName("noatime"))
	}
}

func TestLinuxExtFSFlagAliases(t *testing.T) {
	tests := []struct {
		raw, canonical string
	}{
		{"OPEN:file,fs-append", "fs-append"},
		{"OPEN:file,ext2-append", "fs-append"},
		{"OPEN:file,ext3-append", "fs-append"},
		{"OPEN:file,compr", "fs-compr"},
		{"OPEN:file,dirsync", "fs-dirsync"},
		{"OPEN:file,immutable", "fs-immutable"},
		{"OPEN:file,journal", "fs-journal-data"},
		{"OPEN:file,journal-data", "fs-journal-data"},
		{"OPEN:file,nodump", "fs-nodump"},
		{"OPEN:file,notail", "fs-notail"},
		{"OPEN:file,ext2-notail", "fs-notail"},
		{"OPEN:file,secrm", "fs-secrm"},
		{"OPEN:file,ext2-sync", "fs-sync"},
		{"OPEN:file,topdir", "fs-topdir"},
		{"OPEN:file,unrm", "fs-unrm"},
	}
	for _, tc := range tests {
		s, err := ParseSpec(tc.raw)
		if err != nil {
			t.Fatal(err)
		}
		if !s.BoolOption(tc.canonical) {
			t.Errorf("%s did not set %s", tc.raw, tc.canonical)
		}
	}
	s, err := ParseSpec("OPEN:file,append")
	if err != nil {
		t.Fatal(err)
	}
	if s.BoolOption("fs-append") {
		t.Fatal("append must not alias fs-append")
	}
	s, err = ParseSpec("OPEN:file,sync")
	if err != nil {
		t.Fatal(err)
	}
	if s.BoolOption("fs-sync") {
		t.Fatal("sync must not alias fs-sync")
	}
	if CanonicalOptionName("sync") != "o-sync" {
		t.Fatalf("sync canonicalized to %q", CanonicalOptionName("sync"))
	}
	s, err = ParseSpec("OPEN:file,fs-nodump=0")
	if err != nil {
		t.Fatal(err)
	}
	if s.BoolOption("fs-nodump") {
		t.Fatal("fs-nodump=0 must be false")
	}
	if !s.HasOption("fs-nodump") {
		t.Fatal("fs-nodump=0 must be present")
	}
}

func TestTruncateAlias(t *testing.T) {
	s, err := ParseSpec("FD:3,truncate=4")
	if err != nil {
		t.Fatal(err)
	}
	if CanonicalOptionName("truncate") != "ftruncate" {
		t.Fatalf("truncate canonicalized to %q", CanonicalOptionName("truncate"))
	}
	if !s.HasOption("ftruncate") {
		t.Fatal("truncate= did not normalize to ftruncate")
	}
	if s.OptionValue("ftruncate", "") != "4" {
		t.Fatalf("ftruncate=%q", s.OptionValue("ftruncate", ""))
	}
}

func TestModePermUIDOwnerGIDFtruncateAliases(t *testing.T) {
	tests := []struct {
		raw        string
		canonical  string
		wantValue  string
		aliasCheck string
		wantCanon  string
	}{
		{raw: "FD:3,mode=0600", canonical: "perm", wantValue: "0600", aliasCheck: "mode", wantCanon: "perm"},
		{raw: "FD:3,uid=7", canonical: "user", wantValue: "7", aliasCheck: "uid", wantCanon: "user"},
		{raw: "FD:3,owner=8", canonical: "user", wantValue: "8", aliasCheck: "owner", wantCanon: "user"},
		{raw: "FD:3,gid=9", canonical: "group", wantValue: "9", aliasCheck: "gid", wantCanon: "group"},
		{raw: "FD:3,ftruncate32=4", canonical: "ftruncate", wantValue: "4", aliasCheck: "ftruncate32", wantCanon: "ftruncate"},
		{raw: "FD:3,ftruncate64=5", canonical: "ftruncate", wantValue: "5", aliasCheck: "ftruncate64", wantCanon: "ftruncate"},
	}
	for _, tc := range tests {
		if CanonicalOptionName(tc.aliasCheck) != tc.wantCanon {
			t.Fatalf("%s canonicalized to %q want %q", tc.aliasCheck, CanonicalOptionName(tc.aliasCheck), tc.wantCanon)
		}
		s, err := ParseSpec(tc.raw)
		if err != nil {
			t.Fatal(err)
		}
		if !s.HasOption(tc.canonical) {
			t.Fatalf("%s: missing %s after alias fold", tc.raw, tc.canonical)
		}
		if got := s.OptionValue(tc.canonical, ""); got != tc.wantValue {
			t.Fatalf("%s: %s=%q want %q", tc.raw, tc.canonical, got, tc.wantValue)
		}
	}

	s, err := ParseSpec("FD:3,perm=0644,mode=0600")
	if err != nil {
		t.Fatal(err)
	}
	if s.OptionValue("perm", "") != "0600" {
		t.Fatalf("perm=0644,mode=0600 last-wins got %q", s.OptionValue("perm", ""))
	}
	s, err = ParseSpec("FD:3,mode=0600,perm=0644")
	if err != nil {
		t.Fatal(err)
	}
	if s.OptionValue("perm", "") != "0644" {
		t.Fatalf("mode=0600,perm=0644 last-wins got %q", s.OptionValue("perm", ""))
	}
	s, err = ParseSpec("FD:3,ftruncate=10,ftruncate32=3,ftruncate64=8")
	if err != nil {
		t.Fatal(err)
	}
	if s.OptionValue("ftruncate", "") != "8" {
		t.Fatalf("ftruncate last-wins got %q", s.OptionValue("ftruncate", ""))
	}
}

func TestFileOpenFDExpansionAliases(t *testing.T) {
	tests := []struct {
		raw, canonical, wantValue string
	}{
		{raw: "OPEN:file,sync", canonical: "o-sync", wantValue: "1"},
		{raw: "OPEN:file,o-rdwr", canonical: "rdwr", wantValue: "1"},
		{raw: "OPEN:file,o_rdwr", canonical: "rdwr", wantValue: "1"},
		{raw: "OPEN:file,o_dsync", canonical: "o-dsync", wantValue: "1"},
		{raw: "OPEN:file,noctty", canonical: "o-noctty", wantValue: "1"},
		{raw: "OPEN:file,o-async", canonical: "async", wantValue: "1"},
		{raw: "OPEN:file,nofollow", canonical: "o-nofollow", wantValue: "1"},
		{raw: "FD:3,flock-ex", canonical: "flock", wantValue: "1"},
		{raw: "FD:3,flock-nb", canonical: "flock-nb", wantValue: "1"},
		{raw: "FD:3,lseek64=4", canonical: "lseek", wantValue: "4"},
		{raw: "FD:3,seek-cur=-1", canonical: "seek-cur", wantValue: "-1"},
		{raw: "FD:3,perm-late=0600", canonical: "perm-late", wantValue: "0600"},
		{raw: "FD:3,uid-l=1", canonical: "user-late", wantValue: "1"},
		{raw: "FD:3,gid-l=3", canonical: "group-late", wantValue: "3"},
	}
	for _, tc := range tests {
		s, err := ParseSpec(tc.raw)
		if err != nil {
			t.Fatal(err)
		}
		if !s.HasOption(tc.canonical) {
			t.Fatalf("%s: missing %s", tc.raw, tc.canonical)
		}
		if got := s.OptionValue(tc.canonical, ""); got != tc.wantValue {
			t.Fatalf("%s: %s=%q want %q", tc.raw, tc.canonical, got, tc.wantValue)
		}
	}
	if CanonicalOptionName("seek") != "lseek" {
		t.Fatalf("seek canonicalized to %q", CanonicalOptionName("seek"))
	}
	if CanonicalOptionName("lseek64-end") != "seek-end" {
		t.Fatalf("lseek64-end canonicalized to %q", CanonicalOptionName("lseek64-end"))
	}
}

func TestSocketTypeAlias(t *testing.T) {
	for _, alias := range []string{"so-type", "type"} {
		s, err := ParseSpec("UNIX-LISTEN:/tmp/test.sock," + alias + "=5")
		if err != nil {
			t.Fatal(err)
		}
		if got := s.OptionValue("socktype", ""); got != "5" {
			t.Fatalf("%s: socktype=%q want 5", alias, got)
		}
	}
}

func TestOptionSpellingPreserved(t *testing.T) {
	s, err := ParseSpec("TCP:h:1,so-type=1,O-APPEND,ipv6-join-group=[ff02::2]:lo")
	if err != nil {
		t.Fatal(err)
	}
	if len(s.Options) != 3 {
		t.Fatalf("options=%v", s.Options)
	}
	if s.Options[0].Name != "socktype" || s.Options[0].Spelling != "so-type" || s.Options[0].Value != "1" {
		t.Fatalf("so-type stored as %+v", s.Options[0])
	}
	if s.Options[1].Name != "append" || s.Options[1].Spelling != "o-append" || s.Options[1].Has {
		t.Fatalf("O-APPEND stored as %+v", s.Options[1])
	}
	if s.Options[2].Name != "ipv6-join-group" || s.Options[2].Spelling != "ipv6-join-group" {
		t.Fatalf("ipv6-join-group stored as %+v", s.Options[2])
	}
	if s.Options[0].OriginalSpelling() != "so-type" {
		t.Fatalf("OriginalSpelling=%q", s.Options[0].OriginalSpelling())
	}
}

func TestIPAncillaryAliasesFoldForLastWins(t *testing.T) {
	s, err := ParseSpec("UDP:127.0.0.1:1,ippktinfo,ip-recvttl=1,recvttl=0,ipoptions=x00")
	if err != nil {
		t.Fatal(err)
	}
	if len(s.Options) != 4 {
		t.Fatalf("options=%v", s.Options)
	}
	if s.Options[0].Name != "ip-pktinfo" || s.Options[0].Spelling != "ippktinfo" {
		t.Fatalf("ippktinfo stored as %+v", s.Options[0])
	}
	if s.Options[1].Name != "ip-recvttl" || s.Options[2].Name != "ip-recvttl" {
		t.Fatalf("recvttl aliases stored as %+v %+v", s.Options[1], s.Options[2])
	}
	got, ok := s.OptionNamed("ip-recvttl")
	if !ok || got.Value != "0" {
		t.Fatalf("last-wins ip-recvttl=%+v", got)
	}
	if s.Options[3].Name != "ip-options" || s.Options[3].Spelling != "ipoptions" {
		t.Fatalf("ipoptions stored as %+v", s.Options[3])
	}
	if CanonicalOptionName("ttl") != "ip-ttl" || CanonicalOptionName("tos") != "ip-tos" {
		t.Fatalf("ttl/tos canonical=%q %q", CanonicalOptionName("ttl"), CanonicalOptionName("tos"))
	}
	if CanonicalOptionName("recvdstaddr") != "ip-recvdstaddr" || CanonicalOptionName("iprecvdstaddr") != "ip-recvdstaddr" {
		t.Fatalf("recvdstaddr=%q iprecvdstaddr=%q", CanonicalOptionName("recvdstaddr"), CanonicalOptionName("iprecvdstaddr"))
	}
	if CanonicalOptionName("recvif") != "ip-recvif" {
		t.Fatalf("recvif=%q", CanonicalOptionName("recvif"))
	}
}

func TestSoProtocolAliases(t *testing.T) {
	for _, spec := range []string{
		"VSOCK-LISTEN:9,so-protocol=6",
		"VSOCK-LISTEN:9,so-prototype=6",
		"VSOCK-LISTEN:9,prototype=6",
	} {
		s, err := ParseSpec(spec)
		if err != nil {
			t.Fatalf("%s: %v", spec, err)
		}
		if got := s.OptionValue("so-protocol", ""); got != "6" {
			t.Fatalf("%s: so-protocol=%q", spec, got)
		}
	}
	s, err := ParseSpec("VSOCK-LISTEN:9,protocol-family=inet")
	if err != nil {
		t.Fatal(err)
	}
	if got := s.OptionValue("pf", ""); got != "inet" {
		t.Fatalf("pf=%q", got)
	}
	s, err = ParseSpec("WS:localhost:1,protocol=chat")
	if err != nil {
		t.Fatal(err)
	}
	if s.OptionValue("protocol", "") != "chat" {
		t.Fatalf("WebSocket protocol canonicalized away: %q", s.OptionValue("protocol", ""))
	}
	if s.HasOption("so-protocol") {
		t.Fatal("WebSocket protocol must not alias so-protocol")
	}
}

func TestPOSIXMQOptionAliases(t *testing.T) {
	s, err := ParseSpec("POSIXMQ-SEND:/q,posixmq-priority=3,posixmq-flush,posixmq-maxmsg=8,posixmq-msgsize=128")
	if err != nil {
		t.Fatal(err)
	}
	if s.OptionValue("mq-prio", "") != "3" {
		t.Fatalf("mq-prio %q", s.OptionValue("mq-prio", ""))
	}
	if !s.BoolOption("mq-flush") {
		t.Fatal("mq-flush")
	}
	if s.OptionValue("mq-maxmsg", "") != "8" || s.OptionValue("mq-msgsize", "") != "128" {
		t.Fatalf("maxmsg/msgsize %q %q", s.OptionValue("mq-maxmsg", ""), s.OptionValue("mq-msgsize", ""))
	}
}

func TestParseEmptyOptionValue(t *testing.T) {
	s, err := ParseSpec("TLS:127.0.0.1:443,commonname=,verify=1")
	if err != nil {
		t.Fatal(err)
	}
	o, ok := s.OptionNamed("commonname")
	if !ok || !o.Has {
		t.Fatalf("commonname= missing: %+v", s.Options)
	}
	if o.Value != "" {
		t.Fatalf("commonname=%q want empty", o.Value)
	}
}

func TestOpenSSLCapathAlias(t *testing.T) {
	s, err := ParseSpec("OPENSSL:127.0.0.1:443,openssl-capath=/etc/ssl/certs")
	if err != nil {
		t.Fatal(err)
	}
	if s.Type != "OPENSSL" {
		t.Fatalf("type %q", s.Type)
	}
	if s.OptionValue("capath", "") != "/etc/ssl/certs" {
		t.Fatalf("capath %q", s.OptionValue("capath", ""))
	}
}

func TestTLSCapathAlias(t *testing.T) {
	s, err := ParseSpec("TLS:127.0.0.1:443,tls-capath=/etc/ssl/certs")
	if err != nil {
		t.Fatal(err)
	}
	if s.Type != "TLS" {
		t.Fatalf("type %q", s.Type)
	}
	if s.OptionValue("capath", "") != "/etc/ssl/certs" {
		t.Fatalf("capath %q", s.OptionValue("capath", ""))
	}
}

func TestTLSPublicCatalogAliasesFold(t *testing.T) {
	tests := []struct {
		spec string
		opt  string
		want string
	}{
		{spec: "OPENSSL:127.0.0.1:443,openssl-certificate=/tmp/c.pem", opt: "cert", want: "/tmp/c.pem"},
		{spec: "TLS:127.0.0.1:443,certificate=/tmp/c.pem", opt: "cert", want: "/tmp/c.pem"},
		{spec: "TLS:127.0.0.1:443,openssl-key=/tmp/k.pem", opt: "key", want: "/tmp/k.pem"},
		{spec: "TLS:127.0.0.1:443,openssl-cafile=/tmp/ca.pem", opt: "cafile", want: "/tmp/ca.pem"},
		{spec: "TLS:127.0.0.1:443,openssl-verify=0", opt: "verify", want: "0"},
		{spec: "TLS:127.0.0.1:443,cn=localhost", opt: "commonname", want: "localhost"},
		{spec: "TLS:127.0.0.1:443,cipherlist=ECDHE-ECDSA-AES256-GCM-SHA384", opt: "ciphers", want: "ECDHE-ECDSA-AES256-GCM-SHA384"},
		{spec: "TLS:127.0.0.1:443,no-sni", opt: "nosni", want: "1"},
		{spec: "TLS:127.0.0.1:443,min-proto-version=TLS1.2", opt: "openssl-min-proto-version", want: "TLS1.2"},
		{spec: "TLS:127.0.0.1:443,max-proto-version=TLS1.3", opt: "openssl-max-proto-version", want: "TLS1.3"},
	}
	for _, tc := range tests {
		t.Run(tc.spec, func(t *testing.T) {
			s, err := ParseSpec(tc.spec)
			if err != nil {
				t.Fatal(err)
			}
			if got := s.OptionValue(tc.opt, ""); got != tc.want {
				t.Fatalf("%s=%q want %q", tc.opt, got, tc.want)
			}
		})
	}
}

func TestParseRestoreTTYSystem(t *testing.T) {
	input := `SYSTEM:"stty\ >/tmp/x.stty0;\ /opt/socat-test/socat\ -\,cfmakeraw\ /dev/nul\l >/tmp/x.err;\ stty\ >/tmp/x.stty1",pty,setsid,ctty,stderr`
	spec, err := ParseSpec(input)
	if err != nil {
		t.Fatal(err)
	}
	if spec.Type != "SYSTEM" {
		t.Fatalf("type=%q want SYSTEM", spec.Type)
	}
	wantCommand := "stty >/tmp/x.stty0; /opt/socat-test/socat -,cfmakeraw /dev/null >/tmp/x.err; stty >/tmp/x.stty1"
	if len(spec.Params) != 1 || spec.Params[0] != wantCommand {
		t.Fatalf("params=%q want [%q]", spec.Params, wantCommand)
	}
	wantOptions := []string{"pty", "setsid", "ctty", "stderr"}
	if len(spec.Options) != len(wantOptions) {
		t.Fatalf("options=%+v want %v", spec.Options, wantOptions)
	}
	for i, want := range wantOptions {
		got := spec.Options[i]
		if got.Name != want || got.Has || got.Value != "" {
			t.Errorf("option[%d]=%+v want flag %q", i, got, want)
		}
	}
}

func TestParseWindowsCreatePath(t *testing.T) {
	// Go t.TempDir() uses ...\001\...; \0 must stay a path, not a NUL.
	path := `C:\Users\RUNNER~1\AppData\Local\Temp\TestFileCreate1\001\out.txt`
	ch, err := ParseChannel("CREATE:" + path)
	if err != nil {
		t.Fatal(err)
	}
	if ch.Single == nil || ch.Single.Type != "CREATE" {
		t.Fatalf("got %+v", ch.Single)
	}
	if len(ch.Single.Params) != 1 || ch.Single.Params[0] != path {
		t.Fatalf("params %q", ch.Single.Params)
	}
}

func TestParseWindowsForwardSlashDrive(t *testing.T) {
	path := `C:/Users/foo/out.txt`
	ch, err := ParseChannel("CREATE:" + path)
	if err != nil {
		t.Fatal(err)
	}
	if len(ch.Single.Params) != 1 || ch.Single.Params[0] != path {
		t.Fatalf("params %q", ch.Single.Params)
	}
}

func TestParseWindowsCertOption(t *testing.T) {
	cert := `C:\Users\x\AppData\Local\Temp\t\001\c.pem`
	s, err := ParseSpec("TLS-LISTEN:443,reuseaddr,cert=" + cert)
	if err != nil {
		t.Fatal(err)
	}
	if s.Type != "TLS-LISTEN" || len(s.Params) != 1 || s.Params[0] != "443" {
		t.Fatalf("spec %+v", s)
	}
	if got := s.OptionValue("cert", ""); got != cert {
		t.Fatalf("cert %q", got)
	}
}

func TestParseWindowsQuotedDrive(t *testing.T) {
	path := `C:\Temp\out.txt`
	ch, err := ParseChannel(`CREATE:"` + path + `"`)
	if err != nil {
		t.Fatal(err)
	}
	if len(ch.Single.Params) != 1 || ch.Single.Params[0] != path {
		t.Fatalf("params %q", ch.Single.Params)
	}
}

func TestParseWindowsGOPEN(t *testing.T) {
	path := `C:\foo\bar`
	ch, err := ParseChannel(path)
	if err != nil {
		t.Fatal(err)
	}
	if ch.Single.Type != "GOPEN" || len(ch.Single.Params) != 1 || ch.Single.Params[0] != path {
		t.Fatalf("got %+v", ch.Single)
	}
}

func TestParseWindowsUNC(t *testing.T) {
	path := `\\server\share\file.txt`
	ch, err := ParseChannel("OPEN:" + path)
	if err != nil {
		t.Fatal(err)
	}
	if ch.Single.Type != "OPEN" || len(ch.Single.Params) != 1 || ch.Single.Params[0] != path {
		t.Fatalf("got %+v", ch.Single)
	}
}

func TestParseWindowsDriveRelativePath(t *testing.T) {
	path := `C:foo.txt`
	ch, err := ParseChannel("CREATE:" + path)
	if err != nil {
		t.Fatal(err)
	}
	if len(ch.Single.Params) != 1 || ch.Single.Params[0] != path {
		t.Fatalf("params %q", ch.Single.Params)
	}
}

func TestTextBackslashEscapesRemainActiveOnWindows(t *testing.T) {
	ch, err := ParseChannel(`TEXT:hello\tworld`)
	if err != nil {
		t.Fatal(err)
	}
	if len(ch.Single.Params) != 1 || ch.Single.Params[0] != "hello\tworld" {
		t.Fatalf("params %q", ch.Single.Params)
	}
}
