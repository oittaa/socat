//go:build e2e && relaymatrix && (linux || darwin)

package e2e_test

import "testing"

func TestRelayMatrixUNIX(t *testing.T) {
	runStreamFamilyMatrix(t, streamFamily{
		name: "UNIX",
		unix: true,
	})
}
