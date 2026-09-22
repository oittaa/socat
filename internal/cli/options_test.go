package cli

import (
	"strings"
	"testing"
	"time"

	"github.com/oittaa/socat/internal/parse"
	"github.com/oittaa/socat/internal/xio"
)

func TestSocketAliasesAccepted(t *testing.T) {
	for _, name := range []string{"tcp-nodelay", "tcp-keepalive", "linger"} {
		if err := validateParsed(t, "TCP4:127.0.0.1:1,"+name+"=1"); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestOriginOnlyAcceptedOnWebSocket(t *testing.T) {
	if err := validateParsed(t, "WS:127.0.0.1:80,origin=example"); err != nil {
		t.Fatal(err)
	}
	if err := validateParsed(t, "OPENSSL:127.0.0.1:443,origin=example"); err == nil {
		t.Fatal("accepted WebSocket origin on OPENSSL")
	}
}

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

func TestEnvironmentOptions(t *testing.T) {
	t.Setenv("SOCAT_DEFAULT_LISTEN_IP", "6")
	t.Setenv("SOCAT_PREFERRED_RESOLVE_IP", "0")
	t.Setenv("SOCAT_MAIN_WAIT", "1")
	t.Setenv("SOCAT_FORK_WAIT", "2")
	t.Setenv("SOCAT_TRANSFER_WAIT", "3")
	t.Setenv("LOGNAME", "log-user")
	t.Setenv("USER", "fallback-user")
	t.Setenv("SHELL", "/bin/test-shell")

	opts, mainWait, warnings := environmentOptions()
	if len(warnings) != 0 {
		t.Fatalf("warnings=%v", warnings)
	}
	if opts.DefaultListenIPVersion != xio.IPv6 || opts.PreferredResolveIPVersion != xio.IPvAny {
		t.Fatalf("IP defaults=%v/%v", opts.DefaultListenIPVersion, opts.PreferredResolveIPVersion)
	}
	if opts.SOCKSUser != "log-user" || opts.Shell != "/bin/test-shell" {
		t.Fatalf("process defaults=%q/%q", opts.SOCKSUser, opts.Shell)
	}
	if mainWait != time.Second || opts.ForkWait != 2*time.Second || opts.TransferWait != 3*time.Second {
		t.Fatalf("waits=%v/%v/%v", mainWait, opts.ForkWait, opts.TransferWait)
	}

	t.Setenv("LOGNAME", "")
	opts, _, warnings = environmentOptions()
	if len(warnings) != 0 {
		t.Fatalf("warnings=%v", warnings)
	}
	if opts.SOCKSUser != "fallback-user" {
		t.Fatalf("USER fallback=%q", opts.SOCKSUser)
	}
}

func TestEnvironmentWaitDuration(t *testing.T) {
	for _, value := range []string{"", "invalid", "0", "-1"} {
		if got := environmentWaitDuration(value); got != 0 {
			t.Errorf("%q got %s", value, got)
		}
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
			_, err = xio.PrepareChannel(ch)
			if err == nil || !strings.Contains(err.Error(), "invalid") {
				t.Fatalf("error=%v want invalid", err)
			}
		})
	}
}

func TestAddressDurationUsesCLIUnits(t *testing.T) {
	if err := validateParsed(t, "TCP:127.0.0.1:1,connect-timeout=0.25"); err != nil {
		t.Fatal(err)
	}
	d, err := parseDuration("0.25")
	if err != nil || d != 250*time.Millisecond {
		t.Fatalf("duration=%v err=%v", d, err)
	}
}

func TestResNSAddrRejectsIPv6AtCLI(t *testing.T) {
	err := validateParsed(t, "TCP:127.0.0.1:1,res-nsaddr=[::1]:53")
	if err == nil || !strings.Contains(err.Error(), "IPv6") {
		t.Fatalf("error=%v want IPv6 nameserver rejection", err)
	}
}

func TestValidateSpecOptionsUsesOriginalSpellingNotFoldedName(t *testing.T) {
	spec := parse.Spec{
		Type:   "UDP4-RECV",
		Params: []string{"1"},
		Options: []parse.Option{{
			Name:     "ip-add-membership",
			Spelling: "ipv6-join-group",
			Value:    "[ff02::2]:lo",
			Has:      true,
		}},
	}
	_, err := xio.PrepareSpec(spec)
	if err == nil || !strings.Contains(err.Error(), "not supported") {
		t.Fatalf("folded Name must not bypass spelling groups: %v", err)
	}
}

func TestINTERFACELoIsAcceptedAtCLI(t *testing.T) {
	for _, spec := range []string{"INTERFACE:lo", "IF:lo"} {
		if err := validateParsed(t, spec); err != nil {
			t.Errorf("%s: %v", spec, err)
		}
	}
}
