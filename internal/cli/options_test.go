package cli

import (
	"strings"
	"testing"
	"time"

	"github.com/oittaa/socat/internal/parse"
	"github.com/oittaa/socat/internal/xio"
)

func TestParseDurationRejectsMalformedValues(t *testing.T) {
	for _, value := range []string{"", "banana", "NaN", "+Inf", "1e100"} {
		if _, err := parseDuration(value); err == nil {
			t.Errorf("parseDuration(%q) succeeded", value)
		}
	}
	for _, value := range []string{"1", "1.5", "250ms", "-1"} {
		if _, err := parseDuration(value); err != nil {
			t.Errorf("parseDuration(%q): %v", value, err)
		}
	}
}

func TestParseArgsRejectsMalformedTimeouts(t *testing.T) {
	for _, args := range [][]string{{"-tbanana"}, {"-Tbanana"}} {
		if _, err := ParseArgs(args); err == nil {
			t.Fatalf("ParseArgs(%q) succeeded", args)
		}
	}
}

func TestParseSignalLogMask(t *testing.T) {
	cfg, err := ParseArgs([]string{"-S", "0x80000000"})
	if err != nil {
		t.Fatal(err)
	}
	if cfg.SignalLogMask != 0x80000000 {
		t.Fatalf("SignalLogMask=%#x", cfg.SignalLogMask)
	}
	if _, err := ParseArgs([]string{"-S", "not-a-mask"}); err == nil {
		t.Fatal("invalid -S mask was accepted")
	}
}

func TestFSFlagOptionsRejectNonBoolValues(t *testing.T) {
	names := []string{
		"fs-append", "fs-compr", "fs-dirsync", "fs-immutable", "fs-journal-data",
		"fs-noatime", "fs-nodump", "fs-notail", "fs-secrm", "fs-sync", "fs-topdir", "fs-unrm",
		"nodump",
	}
	for _, name := range names {
		t.Run(name, func(t *testing.T) {
			ch, err := parse.ParseChannel("OPEN:file," + name + "=garbage")
			if err != nil {
				t.Fatal(err)
			}
			err = validateChannelOptions(ch)
			if err == nil || !strings.Contains(err.Error(), "invalid") {
				t.Fatalf("error=%v want invalid", err)
			}
		})
	}
}

func TestAddressDurationUsesCLIUnits(t *testing.T) {
	o := parse.Option{Name: "connect-timeout", Value: "0.25", Has: true}
	if err := validateAddressOptionValue(o); err != nil {
		t.Fatal(err)
	}
	d, err := parseDuration(o.Value)
	if err != nil || d != 250*time.Millisecond {
		t.Fatalf("duration=%v err=%v", d, err)
	}
}

func TestMulticastRemainingOptionsAccepted(t *testing.T) {
	for _, spec := range []string{
		"UDP6:localhost:1,ipv6-multicast-loop=0",
		"UDP6:localhost:1,mcloop6",
		"UDP6:localhost:1,ipv6-join-source-group=[ff3e::1]:lo:[::1]",
		"UDP6:localhost:1,join-source-group=[ff3e::1]:lo:[::1]",
		"UDP4:localhost:1,ip-add-source-membership=232.1.1.1:127.0.0.1:127.0.0.1",
		"UDP4:localhost:1,ip-multicast-ttl=9,ip-multicast-loop=0,ip-multicast-if=127.0.0.1",
		"TCP4-LISTEN:1,ip-freebind,ip-transparent",
	} {
		ch, err := parse.ParseChannel(spec)
		if err != nil {
			t.Fatalf("%s: %v", spec, err)
		}
		if err := validateChannelOptions(ch); err != nil {
			t.Errorf("%s: %v", spec, err)
		}
	}
}

func TestIPv6JoinGroupAcceptedOnIPv6(t *testing.T) {
	for _, spec := range []string{
		"UDP6:localhost:1,ipv6-join-group=[ff02::2]:lo",
		"UDP6-RECV:1,ipv6-join-group=[ff02::2]:lo",
		"TCP6:localhost:1,ipv6-join-group=[ff02::2]:lo",
		"UDP6:localhost:1,join-group=[ff02::2]:lo",
		"TCP6:localhost:1,ipv6-add-membership=[ff02::2]:lo",
	} {
		ch, err := parse.ParseChannel(spec)
		if err != nil {
			t.Fatalf("%s: %v", spec, err)
		}
		if err := validateChannelOptions(ch); err != nil {
			t.Errorf("%s: %v", spec, err)
		}
	}
}

func TestIPAddMembershipAcceptedOnUDP4AndUDP6(t *testing.T) {
	for _, spec := range []string{
		"UDP4:localhost:1,ip-add-membership=224.0.0.1:lo",
		"UDP4-RECV:1,ip-add-membership=224.0.0.1:lo",
		"UDP6:localhost:1,ip-add-membership=[ff02::2]:lo",
		"UDP6-RECV:1,ip-add-membership=[ff02::2]:lo",
		"UDP4:localhost:1,add-membership=224.0.0.1:lo",
		"UDP4:localhost:1,membership=224.0.0.1:lo",
		"UDP6:localhost:1,ip-membership=[ff02::2]:lo",
	} {
		ch, err := parse.ParseChannel(spec)
		if err != nil {
			t.Fatalf("%s: %v", spec, err)
		}
		if err := validateChannelOptions(ch); err != nil {
			t.Errorf("%s: %v", spec, err)
		}
	}
}

func TestValidateSpecOptionsUsesOriginalSpellingNotFoldedName(t *testing.T) {
	spec := parse.Spec{
		Type: "UDP4-RECV",
		Options: []parse.Option{{
			Name:     "ip-add-membership",
			Spelling: "ipv6-join-group",
			Value:    "[ff02::2]:lo",
			Has:      true,
		}},
	}
	err := validateSpecOptions(spec)
	if err == nil || !strings.Contains(err.Error(), "not supported") {
		t.Fatalf("folded Name must not bypass spelling groups: %v", err)
	}
}

func TestTermiosOptionsRecognizedWhenUnsupported(t *testing.T) {
	if xio.FeatureTERMIOS {
		t.Skip("termios is implemented on this platform")
	}
	table := buildSupportedAddressOptions()
	for _, name := range []string{"vintr", "intr", "icanon", "ispeed", "ospeed", "b115200"} {
		if _, ok := table[name]; !ok {
			t.Errorf("option table missing %q on a platform without termios", name)
		}
	}
}

func TestIPAncillaryMatrixWiredIntoCLI(t *testing.T) {
	table := buildSupportedAddressOptions()
	for _, name := range xio.IPAncillaryNames() {
		got, ok := table[name]
		if !ok {
			t.Errorf("matrix option %q missing from CLI table", name)
			continue
		}
		want := xio.IPAncillaryImplementationGroups(name)
		if strings.Join(got.implementationGroups, ",") != strings.Join(want, ",") {
			t.Errorf("%q implementationGroups=%v want %v", name, got.implementationGroups, want)
		}
	}
}

func TestResNSAddrImplementationGroups(t *testing.T) {
	for _, name := range []string{"res-nsaddr", "res-usevc", "ai-all", "ai-passive", "ai-v4mapped", "ai-addrconfig"} {
		got := buildSupportedAddressOptions()[name].implementationGroups
		want := resolverImplementationGroups()
		if strings.Join(got, ",") != strings.Join(want, ",") {
			t.Fatalf("%s implementationGroups=%v want %v", name, got, want)
		}
		for _, group := range []string{xio.GroupUnix, xio.GroupProcess, xio.GroupFiles} {
			if optionImplementedForGroup(group, got) {
				t.Errorf("%s unexpectedly applies to %s", name, group)
			}
		}
	}
}

func TestLingerPublicAliasDoesNotRequireParserFold(t *testing.T) {
	table := buildSupportedAddressOptions()
	linger, ok := table["linger"]
	if !ok {
		t.Fatal("missing linger")
	}
	so, ok := table["so-linger"]
	if !ok {
		t.Fatal("missing so-linger")
	}
	if strings.Join(linger.optionCaps, ",") != strings.Join(so.optionCaps, ",") {
		t.Fatal("linger should share so-linger CLI caps")
	}
	if parse.CanonicalOptionName("linger") != "linger" {
		t.Fatal("linger must not fold at parse")
	}
}

func TestTCPKeepaliveParserAliasUsesKeepaliveCaps(t *testing.T) {
	table := buildSupportedAddressOptions()
	if _, ok := table["tcp-keepalive"]; !ok {
		t.Fatal("constructed tcp-keepalive must be recognized")
	}
	if parse.CanonicalOptionName("tcp-keepalive") != "keepalive" {
		t.Fatal("tcp-keepalive should fold")
	}
}

func TestTLSOptionGroupsComeFromMetadataNotHeading(t *testing.T) {
	cert := buildSupportedAddressOptions()["cert"]
	if !containsString(cert.addressGroups, xio.GroupProxy) {
		t.Fatalf("cert addressGroups=%v", cert.addressGroups)
	}
	path := buildSupportedAddressOptions()["path"]
	if containsString(path.addressGroups, xio.GroupTLS) {
		t.Fatalf("path should not inherit TLS heading groups: %v", path.addressGroups)
	}
}

func containsString(list []string, want string) bool {
	for _, s := range list {
		if s == want {
			return true
		}
	}
	return false
}
