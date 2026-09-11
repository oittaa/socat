package xio

import (
	"context"
	"testing"
	"time"

	"github.com/oittaa/socat/internal/addrconfig"
	"github.com/oittaa/socat/internal/parse"
)

func TestPrepareChannelResolvesAliasesAndOwnsInput(t *testing.T) {
	raw, err := parse.ParseChannel("TCP:example.invalid:9,retry=2,intervall=25ms,crlf")
	if err != nil {
		t.Fatal(err)
	}
	prepared, err := PrepareChannel(raw)
	if err != nil {
		t.Fatal(err)
	}
	if prepared.Single == nil {
		t.Fatal("single address missing")
	}
	if got := prepared.Single.Config.Common.Retry.Policy(); got.MaxAttempts != 3 || got.Interval != 25*time.Millisecond {
		t.Fatalf("retry=%+v", got)
	}
	if prepared.Single.Config.Transfer.LineEnding != addrconfig.LineEndingCRNL {
		t.Fatalf("line ending=%v", prepared.Single.Config.Transfer.LineEnding)
	}
	raw.Single.Params[0] = "changed.invalid"
	raw.Single.Options[0].Value = "0"
	if got := prepared.Single.Config.Params[0]; got != "example.invalid" {
		t.Fatalf("prepared params alias caller memory: %q", got)
	}
	if got := prepared.Single.Config.Common.Retry.Policy().MaxAttempts; got != 3 {
		t.Fatalf("prepared retry alias caller memory: %d", got)
	}
}

func TestPreparedChannelRejectsStaticCommonErrorsBeforeOpen(t *testing.T) {
	raw, err := parse.ParseChannel("TCP:127.0.0.1:9,handshake-timeout=never")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := PrepareChannel(raw); err == nil {
		t.Fatal("invalid static timeout accepted")
	}
}

func TestOpenPreparedChannelDoesNotNeedRawChannel(t *testing.T) {
	raw, err := parse.ParseChannel("STDOUT")
	if err != nil {
		t.Fatal(err)
	}
	prepared, err := PrepareChannel(raw)
	if err != nil {
		t.Fatal(err)
	}
	opened, err := OpenPreparedChannel(context.Background(), prepared, ModeWrite, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = opened.Close() }()
}
