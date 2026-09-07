package dtls13

import (
	"bytes"
	"errors"
	"fmt"
	"testing"
	"time"
)

func TestProtocolAlertClassification(t *testing.T) {
	for _, tc := range []struct {
		err  error
		code byte
	}{
		{errDecode, 50}, {errSignature, 51}, {errCertificate, 42},
		{errFragmentConflict, 47}, {errRecordOverflow, 22},
		{fmt.Errorf("certificate request: %w", errMissingExtension), 109},
		{errGeneral, 117}, {errInternal, 80},
		{errors.New("unmapped local failure"), 80},
	} {
		if got := errorAlert(tc.err); !bytes.Equal(got, []byte{2, tc.code}) {
			t.Fatalf("alert for %v: %x", tc.err, got)
		}
	}
	if errGeneral.Error() != "dtls: general error" {
		t.Fatalf("general_error name: %q", errGeneral)
	}
}

func TestReceiveGeneralErrorAlert(t *testing.T) {
	a, b := handshakeConfigs(t)
	client, server, _ := driveSessions(t, a, b, false, false)
	now := time.Unix(1000, 0)
	w := client.write[client.currentWriteEpoch()]
	packet, err := w.keys.encodeRecord(recordNumber{client.currentWriteEpoch(), w.sequence}, client.handshake.peerCID, contentAlert, []byte{2, 117}, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := server.receive(packet, now); !errors.Is(err, errGeneral) {
		t.Fatalf("receive general_error: %v", err)
	}
}
