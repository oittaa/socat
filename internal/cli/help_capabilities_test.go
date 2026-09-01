//go:build linux || darwin || windows

package cli

import (
	"bytes"
	"strings"
	"testing"
)

func TestUnixCapabilitiesMatchHelpAndVersion(t *testing.T) {
	wantDatagram, wantSeqpacket := expectedUnixCapabilities()

	var version bytes.Buffer
	if err := printVersion(&version); err != nil {
		t.Fatal(err)
	}
	versionText := version.String()
	assertVersionFeature(t, versionText, "UNIX", true)
	assertVersionFeature(t, versionText, "UNIX_DGRAM", wantDatagram)
	assertVersionFeature(t, versionText, "UNIX_SEQPACKET", wantSeqpacket)

	var help bytes.Buffer
	if err := printHelp(&help, 2); err != nil {
		t.Fatal(err)
	}
	helpText := help.String()
	for _, syntax := range []string{
		"UNIX-SENDTO:<filename>",
		"UNIX-RECVFROM:<filename>",
		"UNIX-RECV:<filename>",
		"UNIX-DATAGRAM:<filename>",
	} {
		if got := strings.Contains(helpText, syntax); got != wantDatagram {
			t.Errorf("help presence of %q=%v want %v", syntax, got, wantDatagram)
		}
	}

	wantGeneric := "generic UNIX client; auto-detects stream, seqpacket, or datagram"
	wantConnect := "UNIX stream client; socktype=2/5 selects datagram/seqpacket"
	wantListen := "UNIX stream listener; socktype=5 selects seqpacket"
	wantSocktype := "UNIX type: 1=stream, 2=datagram, 5=seqpacket"
	if !wantSeqpacket {
		wantGeneric = "generic UNIX client; auto-detects stream or datagram"
		wantConnect = "UNIX stream client; socktype=2 selects datagram"
		wantListen = "UNIX stream listener"
		wantSocktype = "UNIX type: 1=stream, 2=datagram"
	}
	if !wantDatagram {
		wantGeneric = "UNIX stream client"
		wantConnect = "UNIX stream client"
		wantSocktype = "UNIX type: 1=stream"
	}
	for _, want := range []string{wantGeneric, wantConnect, wantListen, wantSocktype} {
		if !strings.Contains(helpText, want) {
			t.Errorf("help is missing %q", want)
		}
	}
	if strings.Contains(helpText, "UNIX-CONNECT:<filename>   same as UNIX") {
		t.Error("help still claims strict UNIX-CONNECT is the same as generic UNIX")
	}
	if wantDatagram {
		wantDatagramDesc := "UNIX datagram with a default write destination; receives from any sender"
		if !strings.Contains(helpText, wantDatagramDesc) {
			t.Errorf("help is missing %q", wantDatagramDesc)
		}
	}
}

func assertVersionFeature(t *testing.T, output, name string, enabled bool) {
	t.Helper()
	want := "#undef WITH_" + name
	if enabled {
		want = "#define WITH_" + name + " 1"
	}
	if !strings.Contains(output, want) {
		t.Errorf("-V is missing %q", want)
	}
}
