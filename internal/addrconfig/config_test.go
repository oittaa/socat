package addrconfig

import (
	"strings"
	"testing"
	"time"

	"github.com/oittaa/socat/internal/parse"
)

func decodeSpec(t *testing.T, text string) Address {
	t.Helper()
	spec, err := parse.ParseSpec(text)
	if err != nil {
		t.Fatal(err)
	}
	got, err := Decode(spec, Facts{Type: "TCP", Group: "TCP", Caps: []string{"socket"}})
	if err != nil {
		t.Fatal(err)
	}
	return got
}

func TestDecodeCommonSettings(t *testing.T) {
	got := decodeSpec(t, "TCP:host:9,fork,maxchildren=3,retry=2,forever,interval=250ms,connect-timeout=0,handshake-timeout=2,readbytes=-1,escape=0x1b,ignoreof=off,crlf,shut-close=1")

	if got.Common.MaxChildren != (OptionalInt{Set: true, Value: 3}) {
		t.Fatalf("max children=%+v", got.Common.MaxChildren)
	}
	if policy := got.Common.Retry.Policy(); policy.MaxAttempts != 3 || policy.Interval != 250*time.Millisecond {
		t.Fatalf("retry policy=%+v", policy)
	}
	if !got.Common.Timeouts.Connect.Set || got.Common.Timeouts.Connect.Value != 0 {
		t.Fatalf("connect timeout=%+v", got.Common.Timeouts.Connect)
	}
	if got.Transfer.ReadBytes.Value != ^uint64(0) || got.Transfer.Escape.Value != 0x1b {
		t.Fatalf("transfer values=%+v", got.Transfer)
	}
	if got.Transfer.IgnoreEOF.Value || got.Transfer.LineEnding != LineEndingCRNL || got.Transfer.Shutdown != ShutdownClose {
		t.Fatalf("transfer settings=%+v", got.Transfer)
	}
}

func TestDecodePreservesFlagGrammar(t *testing.T) {
	got := decodeSpec(t, "TCP:host:9,fork=no,forever=maybe,crorlf=,null-eof=false,end-close=0")

	if got.Common.Fork.Enabled.Value {
		t.Fatal("fork=no must disable fork")
	}
	if !got.Common.Retry.Forever.Value {
		t.Fatal("forever=maybe must retain legacy truthiness")
	}
	if got.Transfer.LineEnding != LineEndingRaw || got.Transfer.NullEOF.Value || got.Transfer.EndClose.Value {
		t.Fatalf("flags=%+v", got.Transfer)
	}
}

func TestDecodeRequiresForkForMaxChildrenRegardlessOfOrder(t *testing.T) {
	for _, text := range []string{
		"TCP:host:9,max-children=2",
		"TCP:host:9,max-children=2,fork=0",
	} {
		spec, err := parse.ParseSpec(text)
		if err != nil {
			t.Fatal(err)
		}
		_, err = Decode(spec, Facts{Type: "TCP"})
		if err == nil || !strings.Contains(err.Error(), "max-children not allowed") {
			t.Fatalf("%s: %v", text, err)
		}
	}
	if got := decodeSpec(t, "TCP:host:9,max-children=2,fork"); got.Common.MaxChildren.Value != 2 {
		t.Fatalf("max children=%+v", got.Common.MaxChildren)
	}
}

func TestDecodeStrictOptionalBoolean(t *testing.T) {
	spec, err := parse.ParseSpec("TCP:host:9,handshake-timeout=1,binary=maybe")
	if err != nil {
		t.Fatal(err)
	}
	_, err = Decode(spec, Facts{Type: "TCP"})
	if err == nil || !strings.Contains(err.Error(), `invalid binary "maybe"`) {
		t.Fatalf("error=%v", err)
	}
}

func TestDecodeFileAndTerminalActionsPreserveSourceOrder(t *testing.T) {
	spec, err := parse.ParseSpec("PTY,perm=0600,append=0,lseek=-2,ftruncate=0,echo=0,vintr=0x100,tiocswinsz=-1:70000")
	if err != nil {
		t.Fatal(err)
	}
	config, err := Decode(spec, Facts{Type: "PTY"})
	if err != nil {
		t.Fatal(err)
	}
	if got := config.File.Open.Append; got {
		t.Fatal("append=0 must remain disabled")
	}
	if got := config.File.Actions; len(got) != 4 ||
		got[0].Kind != FileActionPerm ||
		got[1].Kind != FileActionAppend ||
		got[2].Kind != FileActionSeekStart || got[2].Offset != -2 ||
		got[3].Kind != FileActionTruncate || got[3].Offset != 0 {
		t.Fatalf("file actions=%+v", got)
	}
	if got := config.Terminal.Actions; len(got) != 3 ||
		got[0].Kind != TerminalActionFlag || got[0].Name != "echo" || got[0].Enabled ||
		got[1].Kind != TerminalActionChar || got[1].Value != 255 ||
		got[2].Kind != TerminalActionWinSize || got[2].Col != 0 || got[2].Row != 65535 {
		t.Fatalf("terminal actions=%+v", got)
	}
}

func TestDecodeConstructedProcessInput(t *testing.T) {
	spec := parse.Spec{
		Type: "EXEC",
		Options: []parse.Option{
			{Name: "o-wronly"},
			{Name: "fdin", Value: "0", Has: true},
			{Name: "fdout", Value: "", Has: true},
			{Name: "setpgid", Value: "0", Has: true},
			{Name: "pty", Value: "0", Has: true},
			{Name: "openpty"},
		},
	}
	config, err := Decode(spec, Facts{Type: "EXEC"})
	if err != nil {
		t.Fatal(err)
	}
	if config.File.Open.Access != FileAccessWrite {
		t.Fatalf("access=%v want write", config.File.Open.Access)
	}
	if !config.Process.FDIn.Set || config.Process.FDIn.Value != 0 || config.Process.FDOut.Set {
		t.Fatalf("fd maps=%+v/%+v", config.Process.FDIn, config.Process.FDOut)
	}
	if !config.Process.SetPGID.Set || config.Process.SetPGID.Value != 0 || !config.Process.PTY.Value {
		t.Fatalf("process=%+v", config.Process)
	}
}

func TestDecodePTYOptionalValuesAndBareLink(t *testing.T) {
	spec, err := parse.ParseSpec("PTY,pty-wait-slave,pty-interval,sitout-eio=0")
	if err != nil {
		t.Fatal(err)
	}
	config, err := Decode(spec, Facts{Type: "PTY"})
	if err != nil {
		t.Fatal(err)
	}
	if !config.Terminal.WaitSlave.Value || !config.Terminal.WaitInterval.Set || config.Terminal.WaitInterval.Value != time.Second {
		t.Fatalf("wait slave/interval=%+v/%+v", config.Terminal.WaitSlave, config.Terminal.WaitInterval)
	}
	if !config.Terminal.SitoutEIO.Set || config.Terminal.SitoutEIO.Value != 0 {
		t.Fatalf("sitout-eio=%+v", config.Terminal.SitoutEIO)
	}

	zero, err := parse.ParseSpec("PTY,pty-interval=0")
	if err != nil {
		t.Fatal(err)
	}
	config, err = Decode(zero, Facts{Type: "PTY"})
	if err != nil {
		t.Fatal(err)
	}
	if !config.Terminal.WaitInterval.Set || config.Terminal.WaitInterval.Value != 0 {
		t.Fatalf("pty-interval=0 decoded as %+v", config.Terminal.WaitInterval)
	}

	for _, raw := range []string{"PTY,link", "PTY,link="} {
		spec, err := parse.ParseSpec(raw)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := Decode(spec, Facts{Type: "PTY"}); err == nil || !strings.Contains(err.Error(), "link: path required") {
			t.Fatalf("%s: link error=%v", raw, err)
		}
	}
}

func TestDecodeNoInheritActionsPreserveBareAndZero(t *testing.T) {
	spec, err := parse.ParseSpec("FD:3,o-noinherit=0,noinherit")
	if err != nil {
		t.Fatal(err)
	}
	config, err := Decode(spec, Facts{Type: "FD"})
	if err != nil {
		t.Fatal(err)
	}
	if got := config.File.Actions; len(got) != 2 ||
		got[0].Kind != FileActionNoInherit || got[0].Enabled ||
		got[1].Kind != FileActionNoInherit || !got[1].Enabled {
		t.Fatalf("noinherit actions=%+v", got)
	}
}

func TestDecodeNetworkSocketActionsPreserveSourceOrder(t *testing.T) {
	spec, err := parse.ParseSpec("SOCKET-SENDTO:2:2:17:x00007f000001,broadcast=0,setsockopt-socket=1:2:3,so-priority=5")
	if err != nil {
		t.Fatal(err)
	}
	config, err := Decode(spec, Facts{Type: "SOCKET-SENDTO", Group: "Generic socket"})
	if err != nil {
		t.Fatal(err)
	}
	if config.Network.Kind != AddressKindSocket || config.Network.Role != AddressRoleSendTo ||
		config.Network.RawSocket.Domain != 2 || config.Network.RawSocket.Type != 2 ||
		config.Network.RawSocket.Protocol != 17 {
		t.Fatalf("socket=%+v", config.Network)
	}
	got := config.Network.Actions
	if len(got) != 3 ||
		got[0].Kind != SocketActionBroadcast || got[0].Number != 0 ||
		got[1].Kind != SocketActionGeneric || got[1].Phase != SocketPhasePastSocket ||
		got[1].Number != 1 || got[1].Option != 2 || !got[1].Value.IsInt || got[1].Value.Int != 3 ||
		got[2].Kind != SocketActionNamed || got[2].Named != NamedSocketPriority || got[2].Number != 5 {
		t.Fatalf("actions=%+v", got)
	}
}

func TestMembershipFamilyPrefersOriginalSpelling(t *testing.T) {
	spec := parse.Spec{
		Type:   "UDP6-RECV",
		Params: []string{"1"},
		Options: []parse.Option{{
			Name:     "ip-add-membership",
			Spelling: "ipv6-join-group",
			Value:    "[ff02::2]:lo",
			Has:      true,
		}},
	}
	config, err := Decode(spec, Facts{Type: "UDP6-RECV", Group: "UDP"})
	if err != nil {
		t.Fatal(err)
	}
	if len(config.Network.Actions) != 1 {
		t.Fatalf("actions=%+v", config.Network.Actions)
	}
	request := config.Network.Actions[0].Multicast
	if config.Network.Actions[0].Kind != SocketActionMulticast ||
		request.Kind != MulticastJoinIPv6 || request.Name != "ipv6-join-group" {
		t.Fatalf("request=%+v", request)
	}
}

func TestDecodeProtocolSettingsKeepsTypedAndTextualValuesDistinct(t *testing.T) {
	spec, err := parse.ParseSpec("WSS:example.test:443/chat,verify=0,ciphers=ECDHE-RSA-AES128-GCM-SHA256,openssl-min-proto-version=TLS1.2,alpn=chat,path=/override,origin=https://example.test,protocol=Chat")
	if err != nil {
		t.Fatal(err)
	}
	config, err := Decode(spec, Facts{Type: "WSS", Group: "WebSocket (Go extra)"})
	if err != nil {
		t.Fatal(err)
	}
	if config.TLS.Verify.Value || config.TLS.MinVersion != 0x0303 || len(config.TLS.CipherSuites) != 1 ||
		config.TLS.ALPN.Value != "chat" {
		t.Fatalf("TLS=%+v", config.TLS)
	}
	if config.WebSocket.Path.Value != "/override" || config.WebSocket.Origin.Value != "https://example.test" ||
		config.WebSocket.Protocol.Value != "Chat" {
		t.Fatalf("websocket=%+v", config.WebSocket)
	}
}

func TestDecodeTCPWrapDaemonPreservesCaseAndLastWins(t *testing.T) {
	got := decodeSpec(t, "TCP:host:9,tcpwrap=MyDaemon")
	if !got.Network.Peer.TCPWrap.Set || !got.Network.Peer.TCPWrap.Value || got.Network.Peer.TCPWrapDaemon != "MyDaemon" {
		t.Fatalf("tcpwrap=MyDaemon: %+v", got.Network.Peer)
	}

	got = decodeSpec(t, "TCP:host:9,wrap=MyDaemon")
	if got.Network.Peer.TCPWrapDaemon != "MyDaemon" {
		t.Fatalf("wrap alias daemon=%q", got.Network.Peer.TCPWrapDaemon)
	}

	got = decodeSpec(t, "TCP:host:9,tcpwrap=MyDaemon,tcpwrap")
	if !got.Network.Peer.TCPWrap.Value || got.Network.Peer.TCPWrapDaemon != "" {
		t.Fatalf("bare tcpwrap must clear daemon: %+v", got.Network.Peer)
	}

	got = decodeSpec(t, "TCP:host:9,tcpwrap=1")
	if !got.Network.Peer.TCPWrap.Value || got.Network.Peer.TCPWrapDaemon != "" {
		t.Fatalf("tcpwrap=1: %+v", got.Network.Peer)
	}

	got = decodeSpec(t, "TCP:host:9,rcvtimeo=250ms,sndtimeo=1")
	if !got.Common.Timeouts.Read.Set || got.Common.Timeouts.Read.Value != 250*time.Millisecond ||
		!got.Common.Timeouts.Write.Set || got.Common.Timeouts.Write.Value != time.Second {
		t.Fatalf("socket timeouts=%+v", got.Common.Timeouts)
	}
}

func TestDecodeResolverAndNetNS(t *testing.T) {
	got := decodeSpec(t, "TCP:host:9,res-nsaddr=127.0.0.1:53,res-usevc=0,ai-v4mapped,ai-passive=0,ai-addrconfig=1,ai-all,netns=foo")
	if got.Common.Resolver.NameServer.Value != "127.0.0.1:53" || got.Common.Resolver.UseVC.Value ||
		!got.Common.Resolver.V4Mapped.Value || got.Common.Resolver.Passive.Value ||
		!got.Common.Resolver.AddrConfig.Value || !got.Common.Resolver.All.Value {
		t.Fatalf("resolver=%+v", got.Common.Resolver)
	}
	if got.Common.NetNamespace.Value != "foo" {
		t.Fatalf("netns=%+v", got.Common.NetNamespace)
	}

	spec, err := parse.ParseSpec("TCP:host:9,netns=")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Decode(spec, Facts{Type: "TCP"}); err == nil || !strings.Contains(err.Error(), "requires a value") {
		t.Fatalf("empty netns error=%v", err)
	}

	for _, ns := range []string{"::1", "[::1]:53"} {
		spec, err = parse.ParseSpec("TCP:host:9,res-nsaddr=" + ns)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := Decode(spec, Facts{Type: "TCP"}); err == nil || !strings.Contains(err.Error(), "IPv6") {
			t.Fatalf("res-nsaddr=%s error=%v", ns, err)
		}
	}
}

func TestDecodeBindPFAndIPv6V6Only(t *testing.T) {
	got := decodeSpec(t, "TCP:host:9,bind=[::1],sourceport=080,pf=ip4,ipv6-v6only=0")
	if !got.Common.ConnectBind.Set || got.Common.ConnectBind.Value != "[::1]" {
		t.Fatalf("bind=%+v", got.Common.ConnectBind)
	}
	if !got.Network.BindSet || got.Network.Bind.String() != "::1" {
		t.Fatalf("typed bind=%+v", got.Network.Bind)
	}
	if !got.Common.SourcePort.Set || got.Common.SourcePort.Value != "080" {
		t.Fatalf("sourceport=%+v", got.Common.SourcePort)
	}
	if !got.Network.Peer.SourcePortSet || !got.Network.Peer.SourcePort.Numeric || got.Network.Peer.SourcePort.Number != 80 {
		t.Fatalf("typed sourceport=%+v", got.Network.Peer.SourcePort)
	}
	if !got.Common.ProtocolFamily.Set || got.Common.ProtocolFamily.Value != "ip4" {
		t.Fatalf("pf=%+v", got.Common.ProtocolFamily)
	}
	if !got.Common.IPv6V6Only.Set || got.Common.IPv6V6Only.Value {
		t.Fatalf("ipv6-v6only=%+v", got.Common.IPv6V6Only)
	}

	got = decodeSpec(t, "TCP6-LISTEN:9,ipv6-v6only")
	if !got.Common.IPv6V6Only.Set || !got.Common.IPv6V6Only.Value {
		t.Fatalf("bare ipv6-v6only=%+v", got.Common.IPv6V6Only)
	}

	spec, err := parse.ParseSpec("TCP6-LISTEN:9,ipv6-v6only=false")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Decode(spec, Facts{Type: "TCP6-LISTEN"}); err == nil || !strings.Contains(err.Error(), "ipv6-v6only") {
		t.Fatalf("ipv6-v6only=false error=%v", err)
	}
}

func TestDecodeProxyAndDTLSSettings(t *testing.T) {
	proxy, err := parse.ParseSpec("PROXY:proxy.test:target.test:443,http-version=2,h2c=1,proxy-resolve=0,proxy-authorization=user:pass")
	if err != nil {
		t.Fatal(err)
	}
	config, err := Decode(proxy, Facts{Type: "PROXY", Group: "PROXY and SOCKS"})
	if err != nil {
		t.Fatal(err)
	}
	if config.Proxy.HTTPVersion != HTTPVersion2 || !config.Proxy.H2C.Value || config.Proxy.Resolve.Value ||
		config.Proxy.Authorization.Value != "user:pass" {
		t.Fatalf("proxy=%+v", config.Proxy)
	}

	dtls, err := parse.ParseSpec("DTLS:example.test:4444,openssl-min-proto-version=DTLS1.3,dtls-mtu=1200,dtls-migration=0,dtls-unfragmented-probes=1")
	if err != nil {
		t.Fatal(err)
	}
	config, err = Decode(dtls, Facts{Type: "DTLS", Group: "Datagram TLS 1.3"})
	if err != nil {
		t.Fatal(err)
	}
	if config.DTLS.MinVersion.Value != 13 || config.DTLS.MTU.Value != 1200 ||
		config.DTLS.Migration.Value || !config.DTLS.UnfragmentedProbes.Value {
		t.Fatalf("DTLS=%+v", config.DTLS)
	}
}

func TestDecodeUnixBacklogAndKeepalive(t *testing.T) {
	got := decodeSpec(t, "TCP:host:9,unix-bind-tempname=/tmp/x.XXXXXX,unix-tightsocklen=0,backlog=8,keepalive,keepidle=7s,keepintvl=2s,keepcnt=4,nodelay=0")
	if got.Network.UnixBindTempname.Value != "/tmp/x.XXXXXX" {
		t.Fatalf("tempname=%+v", got.Network.UnixBindTempname)
	}
	if !got.Network.UnixTightSocklen.Set || got.Network.UnixTightSocklen.Value {
		t.Fatalf("tightsocklen=%+v", got.Network.UnixTightSocklen)
	}
	if got.Network.Backlog != (OptionalInt{Set: true, Value: 8}) {
		t.Fatalf("backlog=%+v", got.Network.Backlog)
	}
	if !got.Network.KeepAlive.Enable.Value || got.Network.KeepAlive.Idle.Value != 7*time.Second ||
		got.Network.KeepAlive.Interval.Value != 2*time.Second || got.Network.KeepAlive.Count.Value != 4 {
		t.Fatalf("keepalive=%+v", got.Network.KeepAlive)
	}
	if !got.Network.NoDelay.Set || got.Network.NoDelay.Value {
		t.Fatalf("nodelay=%+v", got.Network.NoDelay)
	}

	spec, err := parse.ParseSpec("TCP-LISTEN:9,backlog=0")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Decode(spec, Facts{Type: "TCP-LISTEN"}); err == nil || !strings.Contains(err.Error(), `backlog: invalid value "0"`) {
		t.Fatalf("backlog=0 error=%v", err)
	}
	spec, err = parse.ParseSpec("TCP:host:9,keepidle=-5s")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Decode(spec, Facts{Type: "TCP"}); err == nil || !strings.Contains(err.Error(), "positive") {
		t.Fatalf("keepidle=-5s error=%v", err)
	}
}

func TestDecodeLockfileAndWaitlock(t *testing.T) {
	got := decodeSpec(t, "TCP:host:9,lockfile=/tmp/a.lock")
	if !got.File.Lock.Set || got.File.Lock.Wait || got.File.Lock.Path != "/tmp/a.lock" {
		t.Fatalf("lockfile=%+v", got.File.Lock)
	}
	got = decodeSpec(t, "TCP:host:9,waitlock=/tmp/b.lock")
	if !got.File.Lock.Set || !got.File.Lock.Wait || got.File.Lock.Path != "/tmp/b.lock" {
		t.Fatalf("waitlock=%+v", got.File.Lock)
	}

	spec, err := parse.ParseSpec("TCP:host:9,lockfile=/tmp/a.lock,waitlock=/tmp/b.lock")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Decode(spec, Facts{Type: "TCP"}); err == nil || !strings.Contains(err.Error(), "only one use") {
		t.Fatalf("dual lock error=%v", err)
	}
	spec, err = parse.ParseSpec("TCP:host:9,lockfile")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Decode(spec, Facts{Type: "TCP"}); err == nil || !strings.Contains(err.Error(), "requires a value") {
		t.Fatalf("bare lockfile error=%v", err)
	}
}

func TestDecodeVSOCKBind(t *testing.T) {
	spec, err := parse.ParseSpec("VSOCK-CONNECT:2:22,bind=3:9")
	if err != nil {
		t.Fatal(err)
	}
	got, err := Decode(spec, Facts{Type: "VSOCK-CONNECT", Group: "VSOCK (Linux)"})
	if err != nil {
		t.Fatal(err)
	}
	if !got.Network.VSOCK.BindSet || !got.Network.VSOCK.BindHasPort ||
		got.Network.VSOCK.Bind.CID != 3 || got.Network.VSOCK.Bind.Port != 9 {
		t.Fatalf("vsock bind=%+v", got.Network.VSOCK)
	}

	listen, err := parse.ParseSpec("VSOCK-LISTEN:22,bind=5")
	if err != nil {
		t.Fatal(err)
	}
	got, err = Decode(listen, Facts{Type: "VSOCK-LISTEN", Group: "VSOCK (Linux)"})
	if err != nil {
		t.Fatal(err)
	}
	if !got.Network.VSOCK.BindSet || got.Network.VSOCK.BindHasPort || got.Network.VSOCK.Bind.CID != 5 {
		t.Fatalf("vsock listen bind=%+v", got.Network.VSOCK)
	}
}

func TestDecodeParentSignals(t *testing.T) {
	got := decodeSpec(t, "EXEC:true,sighup,sigint,sighup")
	want := []ParentSignal{ParentSignalHUP, ParentSignalINT, ParentSignalHUP}
	if len(got.Process.ParentSignals) != len(want) {
		t.Fatalf("signals=%v", got.Process.ParentSignals)
	}
	for i, sig := range want {
		if got.Process.ParentSignals[i] != sig {
			t.Fatalf("signals=%v want %v", got.Process.ParentSignals, want)
		}
	}
	spec, err := parse.ParseSpec("EXEC:true,sighup=0")
	if err != nil {
		t.Fatal(err)
	}
	_, err = Decode(spec, Facts{Type: "EXEC"})
	if err == nil || !strings.Contains(err.Error(), "no value permitted") {
		t.Fatalf("error=%v want no value permitted", err)
	}
}

func TestDecodeTLSPlaintextLastWins(t *testing.T) {
	got := decodeSpec(t, "PROXY:h:h:9,cert=x,fips=1,verify=0")
	if got.TLS.LastHiddenName != "fips" {
		t.Fatalf("hidden=%q", got.TLS.LastHiddenName)
	}
	if got.TLS.LastPlaintextName != "verify" {
		t.Fatalf("plaintext=%q", got.TLS.LastPlaintextName)
	}
}
