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
