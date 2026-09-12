//go:build e2e && (linux || darwin)

package e2e_test

import "testing"

func TestOptionCapabilityAppendOnTCPAccepted(t *testing.T) {
	payload := []byte("append-ok\n")
	out, err, stderr := runTCPAcceptedOption(t, "append", payload)
	if checkErr := acceptedConnectedResult(out, err, payload, stderr); checkErr != nil {
		t.Fatal(checkErr)
	}
}
