package dtls13

import (
	"bytes"
	"fmt"
	"testing"
)

func TestProtocolAlertClassification(t *testing.T) {
	for _, tc := range []struct {
		err  error
		code byte
	}{
		{errDecode, 50}, {errSignature, 51}, {errCertificate, 42},
		{errFragmentConflict, 47}, {errRecordOverflow, 22},
		{fmt.Errorf("certificate request: %w", errMissingExtension), 109},
	} {
		if got := errorAlert(tc.err); !bytes.Equal(got, []byte{2, tc.code}) {
			t.Fatalf("alert for %v: %x", tc.err, got)
		}
	}
}
