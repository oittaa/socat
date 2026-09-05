package dtls13

import (
	"bytes"
	"encoding/json"
	"os"
	"testing"
)

func TestKeyScheduleVectors(t *testing.T) {
	data, err := os.ReadFile("testdata/schedule.json")
	if err != nil {
		t.Fatal(err)
	}
	var vectors map[string]map[string]string
	if err := json.Unmarshal(data, &vectors); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name  string
		suite uint16
	}{{"sha256", aes128GCM}, {"sha384", aes256GCM}} {
		t.Run(tc.name, func(t *testing.T) {
			v, ok := vectors[tc.name]
			if !ok {
				t.Fatal("missing vector")
			}
			check := func(name string, got []byte) {
				t.Helper()
				want, ok := v[name]
				if !ok {
					t.Fatalf("missing %s", name)
				}
				if !bytes.Equal(got, decodeHex(t, want)) {
					t.Fatalf("%s: %x; want %s", name, got, want)
				}
			}
			s, err := newKeySchedule(tc.suite, decodeHex(t, v["shared"]), decodeHex(t, v["hello"]))
			if err != nil {
				t.Fatal(err)
			}
			check("master", s.master)
			check("client_handshake", s.clientHandshake)
			check("server_handshake", s.serverHandshake)
			for _, m := range []handshakeMessage{
				{typ: msgEncryptedExtensions, sequence: 1, epoch: 2, body: []byte("extensions")},
				{typ: msgCertificate, sequence: 2, epoch: 2, body: []byte("certificate")},
				{typ: msgCertificateVerify, sequence: 3, epoch: 2, body: []byte("certificate verify")},
			} {
				if err := s.write(m); err != nil {
					t.Fatal(err)
				}
			}
			finished, err := s.finished(s.serverHandshake)
			if err != nil {
				t.Fatal(err)
			}
			check("server_finished", finished)
			if err := s.write(handshakeMessage{typ: msgFinished, sequence: 4, epoch: 2, body: finished}); err != nil {
				t.Fatal(err)
			}
			clientFinished, err := s.finished(s.clientHandshake)
			if err != nil {
				t.Fatal(err)
			}
			check("client_finished", clientFinished)
			client, server, err := s.applicationSecrets()
			if err != nil {
				t.Fatal(err)
			}
			check("client_application", client)
			check("server_application", server)
			update, err := nextTrafficSecret(tc.suite, client)
			if err != nil {
				t.Fatal(err)
			}
			check("client_update", update)
			messages := make([][]byte, 0, 3)
			for _, m := range []handshakeMessage{
				{typ: msgClientHello, body: []byte("first client hello")},
				{typ: msgServerHello, body: []byte("retry cookie")},
				{typ: msgClientHello, sequence: 1, body: []byte("second client hello")},
			} {
				wire, err := m.transcript()
				if err != nil {
					t.Fatal(err)
				}
				messages = append(messages, wire)
			}
			retry, err := retryTranscript(tc.suite, messages[0], messages[1], messages[2])
			if err != nil {
				t.Fatal(err)
			}
			check("retry_transcript", retry)
		})
	}
}

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
