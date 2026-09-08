package dtls13

import (
	"testing"
)

func TestKeyScheduleRejectsInvalidKeyMaterial(t *testing.T) {
	if _, err := newKeySchedule(0, []byte{1}, nil); err == nil {
		t.Fatal("accepted unsupported suite")
	}
	if _, err := newKeySchedule(aes128GCM, nil, nil); err == nil {
		t.Fatal("accepted absent shared secret")
	}
	s, err := newKeySchedule(aes128GCM, make([]byte, 32), nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.finished([]byte{1}); err == nil {
		t.Fatal("accepted short handshake traffic secret")
	}
	if _, err := nextTrafficSecret(aes128GCM, []byte{1}); err == nil {
		t.Fatal("accepted short application traffic secret")
	}
}
