//go:build e2e && windows

package e2e_test

import (
	"bytes"
	"testing"
)

func TestOptionCapabilityAppendOnTCPRejected(t *testing.T) {
	out, err, stderr := runTCPAcceptedOption(t, "append", []byte("append-ok\n"))
	requireCleanFailure(t, out, err)
	want := "fcntl O_APPEND is not supported on windows"
	if !bytes.Contains(out, []byte(want)) {
		t.Fatalf("output=%q want substring %q srv=%s", out, want, stderr)
	}
}
