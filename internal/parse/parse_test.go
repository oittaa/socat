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
