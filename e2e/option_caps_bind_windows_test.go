//go:build e2e && windows

package e2e_test

import "testing"

func TestOptionCapabilityAppendOnTCPRejected(t *testing.T) {
	out, err, stderr := runTCPAcceptedOption(t, "append", []byte("append-ok\n"))
	if checkErr := rejectedOptionResult(out, err, "fcntl O_APPEND is not supported on windows"); checkErr != nil {
		t.Fatalf("%v srv=%s", checkErr, stderr)
	}
}
