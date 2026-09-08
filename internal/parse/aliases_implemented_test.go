package parse

import (
	"testing"
)

func TestRawRemainsDistinctFromCFMakeRaw(t *testing.T) {
	if got := CanonicalOptionName("raw"); got != "raw" {
		t.Fatalf("CanonicalOptionName(raw)=%q want raw", got)
	}
	if got := CanonicalOptionName("termios-cfmakeraw"); got != "cfmakeraw" {
		t.Fatalf("CanonicalOptionName(termios-cfmakeraw)=%q want cfmakeraw", got)
	}
}
