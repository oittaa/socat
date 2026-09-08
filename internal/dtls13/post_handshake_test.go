package dtls13

import (
	"bytes"
	"encoding/binary"
	"errors"
	"testing"
	"time"
)

func deliverSessionPackets(t *testing.T, client, server *session, packets *[]testDatagram, now time.Time) [][]byte {
	t.Helper()
	var application [][]byte
	for step := 0; len(*packets) != 0; step++ {
		if step > 1000 {
			t.Fatal("session packet loop exceeded event bound")
		}
		p := (*packets)[0]
		*packets = (*packets)[1:]
		destination := client
		if p.fromClient {
			destination = server
		}
		data, err := destination.receive(p.data, now)
		if err != nil {
			t.Fatalf("receive (client=%t): %v", destination.handshake.client, err)
		}
		application = append(application, data...)
	}
	return application
}

func TestKeyUpdateLostACK(t *testing.T) {
	a, b := handshakeConfigs(t)
	client, server, packets := driveSessions(t, a, b, false, false)
	now := time.Unix(1000, 0)
	if err := client.requestKeyUpdate(false, now); err != nil {
		t.Fatal(err)
	}
	if err := client.application([]byte("wait")); !errors.Is(err, errOperationPending) {
		t.Fatalf("write did not wait for key acknowledgement: %v", err)
	}
	update := (*packets)[0].data
	*packets = nil
	if _, err := server.receive(update, now); err != nil {
		t.Fatal(err)
	}
	if len(*packets) != 1 {
		t.Fatal("key update was not acknowledged")
	}
	*packets = nil // Lose the ACK, forcing a fresh old-epoch transmission.
	if server.read[3] == nil || client.currentWriteEpoch() != 3 {
		t.Fatal("old keys removed before acknowledgement")
	}
	now = client.deadline()
	if err := client.tick(now); err != nil {
		t.Fatal(err)
	}
	if len(*packets) != 1 || bytes.Equal((*packets)[0].data, update) {
		t.Fatal("retransmission did not use a fresh record number")
	}
	deliverSessionPackets(t, client, server, packets, now)
	if client.currentWriteEpoch() != 4 || !client.deadline().IsZero() {
		t.Fatal("acknowledged update did not activate new keys and cancel retry")
	}
	if err := client.application([]byte("new epoch")); err != nil {
		t.Fatal(err)
	}
	data := deliverSessionPackets(t, client, server, packets, now)
	if len(data) != 1 || string(data[0]) != "new epoch" || server.read[3] != nil {
		t.Fatal("new key traffic failed or obsolete keys remained")
	}
}

func TestApplicationRotatesKeysBeforeRecordLimit(t *testing.T) {
	a, b := handshakeConfigs(t)
	client, server, packets := driveSessions(t, a, b, false, false)
	now := time.Unix(1000, 0)
	client.write[3].sequence = 1<<24 - 1024
	// Bring the receiver's truncated record-number window to the same point.
	if !server.read[3].window.accept(1<<24 - 1025) {
		t.Fatal("could not advance the receiver's record window")
	}
	if err := client.application([]byte("limit")); !errors.Is(err, errOperationPending) {
		t.Fatalf("application write at the key limit = %v", err)
	}
	if err := client.advancePost(now); err != nil {
		t.Fatal(err)
	}
	deliverSessionPackets(t, client, server, packets, now)
	if client.currentWriteEpoch() != 4 {
		t.Fatal("key usage limit did not advance the write epoch")
	}
	if err := client.application([]byte("fresh keys")); err != nil {
		t.Fatal(err)
	}
	data := deliverSessionPackets(t, client, server, packets, now)
	if len(data) != 1 || string(data[0]) != "fresh keys" {
		t.Fatal("application write did not resume with fresh keys")
	}
}

func TestKeyUpdateSimultaneousRequestsAndEpochBits(t *testing.T) {
	a, b := handshakeConfigs(t)
	client, server, packets := driveSessions(t, a, b, false, false)
	now := time.Unix(1000, 0)
	for i := 0; i < 6; i++ {
		if err := client.requestKeyUpdate(true, now); err != nil {
			t.Fatal(err)
		}
		if err := server.requestKeyUpdate(true, now); err != nil {
			t.Fatal(err)
		}
		deliverSessionPackets(t, client, server, packets, now)
		for _, s := range []*session{client, server} {
			if s.updating || s.updatePending || !s.deadline().IsZero() {
				t.Fatal("simultaneous key updates did not settle")
			}
			if err := s.application([]byte("epoch transition")); err != nil {
				t.Fatal(err)
			}
		}
		if data := deliverSessionPackets(t, client, server, packets, now); len(data) != 2 {
			t.Fatal("application traffic failed across epoch bit rollover")
		}
		if len(client.read) > 2 || len(server.read) > 2 || len(client.write) != 1 || len(server.write) != 1 {
			t.Fatal("key updates accumulated obsolete key material")
		}
	}
}

func TestKeyUpdateMalformedAndWrongEpoch(t *testing.T) {
	for _, body := range [][]byte{nil, {0, 0}, {2}} {
		a, b := handshakeConfigs(t)
		client, server, packets := driveSessions(t, a, b, false, false)
		m, err := client.handshake.message(msgKeyUpdate, 3, body)
		if err != nil {
			t.Fatal(err)
		}
		fragment := fragmentFor(t, m, 0, len(body))
		if _, err := client.sendRecord(3, contentHandshake, fragment); err != nil {
			t.Fatal(err)
		}
		if _, err := server.receive((*packets)[0].data, time.Unix(1000, 0)); err == nil {
			t.Fatalf("accepted malformed KeyUpdate %x", body)
		}
	}
}

func TestClosureUsesRecordOrder(t *testing.T) {
	a, b := handshakeConfigs(t)
	client, server, packets := driveSessions(t, a, b, false, false)
	if err := client.application([]byte("before close")); err != nil {
		t.Fatal(err)
	}
	if _, err := client.sendRecord(3, contentAlert, []byte{1, 0}); err != nil {
		t.Fatal(err)
	}
	if err := client.application([]byte("after close")); err != nil {
		t.Fatal(err)
	}
	ordered := *packets
	*packets = nil
	for _, index := range []int{1, 2, 0} {
		data, err := server.receive(ordered[index].data, time.Unix(1000, 0))
		if err != nil {
			t.Fatal(err)
		}
		if index == 0 {
			if len(data) != 1 || string(data[0]) != "before close" {
				t.Fatal("closure discarded reordered earlier record")
			}
		} else if len(data) != 0 {
			t.Fatal("closure allowed a later application record")
		}
	}
}

func TestCompletedSessionIgnoresPlaintextAfterSecretCleanup(t *testing.T) {
	a, b := handshakeConfigs(t)
	client, server, packets := driveSessions(t, a, b, false, false)
	if server.handshake.schedule != nil || client.handshake.schedule != nil {
		t.Fatal("acknowledged handshake retained its master and ephemeral state")
	}
	forged, err := encodePlainRecord(contentAlert, 600, []byte{1, 0})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := server.receive(forged, time.Unix(1000, 0)); err != nil || server.peerClosed != nil {
		t.Fatalf("plaintext alert affected an authenticated session: %v", err)
	}
	if err := client.application([]byte("still authenticated")); err != nil {
		t.Fatal(err)
	}
	if data := deliverSessionPackets(t, client, server, packets, time.Unix(1000, 0)); len(data) != 1 {
		t.Fatal("plaintext injection prevented authenticated application traffic")
	}
}

const rfc9147HandshakeHeader = 12

func rfc9147Uint24(b []byte) int { return int(b[0])<<16 | int(b[1])<<8 | int(b[2]) }

// rfc9147RecordContent decrypts one DTLS 1.3 ciphertext using RFC 9147 §4
// headers and the AEAD, without handshakeMessage encoding.
func rfc9147RecordContent(datagram []byte, keys *trafficKeys, cidLen int, expectedSeq uint64) (byte, []byte, error) {
	r, rest, err := parseRecord(datagram, cidLen)
	if err != nil {
		return 0, nil, err
	}
	if len(rest) != 0 || !r.encrypted {
		return 0, nil, errRecord
	}
	mask, err := keys.mask(r.body)
	if err != nil {
		return 0, nil, err
	}
	header := bytes.Clone(r.header)
	var truncated uint64
	for i := range r.seqLen {
		header[r.seqOffset+i] ^= mask[i]
		truncated = truncated<<8 | uint64(header[r.seqOffset+i])
	}
	inner, err := keys.open(header, reconstructSequence(truncated, r.seqLen, expectedSeq), r.body)
	if err != nil {
		return 0, nil, err
	}
	end := len(inner) - 1
	for end >= 0 && inner[end] == 0 {
		end--
	}
	if end < 0 || !validContentType(inner[end]) {
		return 0, nil, errRecord
	}
	return inner[end], inner[:end], nil
}

// rfc9147KeyUpdateFlag reads the KeyUpdateRequest from a DTLSHandshake body
// (RFC 9147 §5.2 / RFC 9846 §4.7.3). It does not use handshakeMessage.fragment.
func rfc9147KeyUpdateFlag(plaintext []byte) (byte, bool) {
	if len(plaintext) < rfc9147HandshakeHeader+1 || plaintext[0] != msgKeyUpdate {
		return 0, false
	}
	length := rfc9147Uint24(plaintext[1:4])
	offset := rfc9147Uint24(plaintext[6:9])
	fragLen := rfc9147Uint24(plaintext[9:12])
	if offset != 0 || fragLen != length || length != 1 || len(plaintext) < rfc9147HandshakeHeader+fragLen {
		return 0, false
	}
	flag := plaintext[rfc9147HandshakeHeader]
	if flag > 1 {
		return 0, false
	}
	return flag, true
}

func sessionCIDLen(s *session) int {
	if s.handshake.cidNegotiated {
		return len(s.handshake.peerCID)
	}
	return 0
}

func senderWriteKeys(s *session) (*trafficKeys, uint64) {
	w := s.write[s.currentWriteEpoch()]
	return w.keys, w.sequence
}

func takeFrom(packets *[]testDatagram, fromClient bool) [][]byte {
	var taken [][]byte
	rest := (*packets)[:0]
	for _, p := range *packets {
		if p.fromClient == fromClient {
			taken = append(taken, p.data)
		} else {
			rest = append(rest, p)
		}
	}
	*packets = rest
	return taken
}

func recordContentFrom(datagram []byte, sender *session) (byte, []byte, error) {
	keys, expected := senderWriteKeys(sender)
	return rfc9147RecordContent(datagram, keys, sessionCIDLen(sender), expected)
}

func keyUpdateFlagOnWire(t *testing.T, datagram []byte, sender *session) (byte, bool) {
	t.Helper()
	typ, body, err := recordContentFrom(datagram, sender)
	if err != nil || typ != contentHandshake {
		return 0, false
	}
	return rfc9147KeyUpdateFlag(body)
}

func collectKeyUpdateFlags(t *testing.T, datagrams [][]byte, sender *session) []byte {
	t.Helper()
	var flags []byte
	for _, datagram := range datagrams {
		if flag, ok := keyUpdateFlagOnWire(t, datagram, sender); ok {
			flags = append(flags, flag)
		}
	}
	return flags
}

func deliverDatagrams(t *testing.T, destination *session, datagrams [][]byte, now time.Time) [][]byte {
	t.Helper()
	var application [][]byte
	for _, datagram := range datagrams {
		data, err := destination.receive(datagram, now)
		if err != nil {
			t.Fatal(err)
		}
		application = append(application, data...)
	}
	return application
}

func TestKeyUpdateRequestedWaitsForPeerUpdate(t *testing.T) {
	for _, clientInitiated := range []bool{true, false} {
		t.Run(map[bool]string{true: "client", false: "server"}[clientInitiated], func(t *testing.T) {
			a, b := handshakeConfigs(t)
			client, server, packets := driveSessions(t, a, b, false, false)
			now := time.Unix(1000, 0)
			sender, receiver := client, server
			if !clientInitiated {
				sender, receiver = server, client
			}
			if err := sender.requestKeyUpdate(true, now); err != nil {
				t.Fatal(err)
			}
			first := takeFrom(packets, sender.handshake.client)
			if flags := collectKeyUpdateFlags(t, first, sender); !bytes.Equal(flags, []byte{1}) {
				t.Fatalf("first KeyUpdate flags = %v, want [1]", flags)
			}
			deliverDatagrams(t, receiver, first, now)
			reply := takeFrom(packets, receiver.handshake.client)
			var acks, withheld [][]byte
			for _, datagram := range reply {
				typ, _, err := recordContentFrom(datagram, receiver)
				if err != nil {
					t.Fatal(err)
				}
				if typ == contentHandshake {
					withheld = append(withheld, datagram)
				} else {
					acks = append(acks, datagram)
				}
			}
			if len(withheld) == 0 {
				t.Fatal("peer did not produce a KeyUpdate to withhold")
			}
			deliverDatagrams(t, sender, acks, now)
			if sender.currentWriteEpoch() < 4 {
				t.Fatal("ACK did not complete the local sending-key update")
			}
			if err := sender.application([]byte("after local ack")); err != nil {
				t.Fatal(err)
			}
			if app := takeFrom(packets, sender.handshake.client); len(app) == 0 {
				t.Fatal("application write blocked while awaiting a peer KeyUpdate")
			}
			if err := sender.requestKeyUpdate(true, now); err != nil {
				t.Fatal(err)
			}
			second := takeFrom(packets, sender.handshake.client)
			if flags := collectKeyUpdateFlags(t, second, sender); !bytes.Equal(flags, []byte{0}) {
				t.Fatalf("second KeyUpdate flags = %v, want [0] (RFC 9846 §4.7.3)", flags)
			}
			deliverDatagrams(t, receiver, second, now)
			deliverDatagrams(t, sender, takeFrom(packets, receiver.handshake.client), now)
			deliverDatagrams(t, sender, withheld, now)
			deliverSessionPackets(t, client, server, packets, now)
			if err := sender.requestKeyUpdate(true, now); err != nil {
				t.Fatal(err)
			}
			third := takeFrom(packets, sender.handshake.client)
			if flags := collectKeyUpdateFlags(t, third, sender); !bytes.Equal(flags, []byte{1}) {
				t.Fatalf("KeyUpdate after accepted peer update flags = %v, want [1]", flags)
			}
		})
	}
}

func TestKeyUpdatePeerArrivesBeforeACK(t *testing.T) {
	a, b := handshakeConfigs(t)
	client, server, packets := driveSessions(t, a, b, false, false)
	now := time.Unix(1000, 0)
	if err := client.requestKeyUpdate(true, now); err != nil {
		t.Fatal(err)
	}
	first := takeFrom(packets, true)
	deliverDatagrams(t, server, first, now)
	reply := takeFrom(packets, false)
	var acks, peerUpdate [][]byte
	for _, datagram := range reply {
		typ, _, err := recordContentFrom(datagram, server)
		if err != nil {
			t.Fatal(err)
		}
		if typ == contentHandshake {
			peerUpdate = append(peerUpdate, datagram)
		} else {
			acks = append(acks, datagram)
		}
	}
	deliverDatagrams(t, client, peerUpdate, now)
	deliverDatagrams(t, client, acks, now)
	deliverSessionPackets(t, client, server, packets, now)
	if err := client.requestKeyUpdate(true, now); err != nil {
		t.Fatal(err)
	}
	if flags := collectKeyUpdateFlags(t, takeFrom(packets, true), client); !bytes.Equal(flags, []byte{1}) {
		t.Fatalf("KeyUpdate after peer-before-ACK flags = %v, want [1]", flags)
	}
}

func TestKeyUpdateRequestedRetransmitKeepsBody(t *testing.T) {
	a, b := handshakeConfigs(t)
	client, server, packets := driveSessions(t, a, b, false, false)
	now := time.Unix(1000, 0)
	if err := client.requestKeyUpdate(true, now); err != nil {
		t.Fatal(err)
	}
	first := takeFrom(packets, true)
	if flags := collectKeyUpdateFlags(t, first, client); !bytes.Equal(flags, []byte{1}) {
		t.Fatalf("initial flags = %v, want [1]", flags)
	}
	deliverDatagrams(t, server, first, now)
	*packets = nil
	now = client.deadline()
	if err := client.tick(now); err != nil {
		t.Fatal(err)
	}
	retransmit := takeFrom(packets, true)
	if flags := collectKeyUpdateFlags(t, retransmit, client); !bytes.Equal(flags, []byte{1}) {
		t.Fatalf("retransmit flags = %v, want original [1]", flags)
	}
	if len(retransmit) != 1 || bytes.Equal(retransmit[0], first[0]) {
		t.Fatal("retransmission did not use a fresh record number")
	}
}

func TestKeyUpdateInvalidAndReplayDoNotClearOutstandingRequest(t *testing.T) {
	a, b := handshakeConfigs(t)
	client, server, packets := driveSessions(t, a, b, false, false)
	now := time.Unix(1000, 0)
	if err := client.requestKeyUpdate(true, now); err != nil {
		t.Fatal(err)
	}
	first := takeFrom(packets, true)
	deliverDatagrams(t, server, first, now)
	reply := takeFrom(packets, false)
	var acks [][]byte
	for _, datagram := range reply {
		typ, _, err := recordContentFrom(datagram, server)
		if err != nil {
			t.Fatal(err)
		}
		if typ != contentHandshake {
			acks = append(acks, datagram)
		}
	}
	if len(acks) == 0 {
		t.Fatal("missing ACK of the local KeyUpdate")
	}
	deliverDatagrams(t, client, acks, now)
	forged, err := encodePlainRecord(contentHandshake, 700, []byte{msgKeyUpdate, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 1, 1})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.receive(forged, now); err != nil {
		t.Fatalf("unauthenticated handshake affected the session: %v", err)
	}
	if _, err := client.receive(first[0], now); err != nil {
		t.Fatalf("replayed local KeyUpdate: %v", err)
	}
	corrupt := bytes.Clone(acks[0])
	corrupt[len(corrupt)-1] ^= 0xff
	if _, err := client.receive(corrupt, now); err != nil {
		t.Fatalf("failed authentication affected the session: %v", err)
	}
	if err := client.receivePost(handshakeMessage{typ: msgKeyUpdate, epoch: client.readApplicationEpoch, body: []byte{2}}, now); err == nil {
		t.Fatal("accepted illegal KeyUpdateRequest")
	}
	if err := client.requestKeyUpdate(true, now); err != nil {
		t.Fatal(err)
	}
	if flags := collectKeyUpdateFlags(t, takeFrom(packets, true), client); !bytes.Equal(flags, []byte{0}) {
		t.Fatalf("invalid records cleared outstanding request: flags = %v, want [0]", flags)
	}
}

func TestKeyUpdateAutomaticRekeyWhileAwaitingPeer(t *testing.T) {
	a, b := handshakeConfigs(t)
	client, server, packets := driveSessions(t, a, b, false, false)
	now := time.Unix(1000, 0)
	if err := client.requestKeyUpdate(true, now); err != nil {
		t.Fatal(err)
	}
	first := takeFrom(packets, true)
	deliverDatagrams(t, server, first, now)
	reply := takeFrom(packets, false)
	var acks [][]byte
	for _, datagram := range reply {
		typ, _, err := recordContentFrom(datagram, server)
		if err != nil {
			t.Fatal(err)
		}
		if typ != contentHandshake {
			acks = append(acks, datagram)
		}
	}
	deliverDatagrams(t, client, acks, now)
	epoch := client.currentWriteEpoch()
	client.write[epoch].sequence = client.write[epoch].keys.recordLimit - 1024
	if err := client.application([]byte("limit")); !errors.Is(err, errOperationPending) {
		t.Fatalf("limit write = %v", err)
	}
	if err := client.advancePost(now); err != nil {
		t.Fatal(err)
	}
	if flags := collectKeyUpdateFlags(t, takeFrom(packets, true), client); !bytes.Equal(flags, []byte{0}) {
		t.Fatalf("automatic rekey flags = %v, want [0]", flags)
	}
}

func TestKeyUpdateSimultaneousFlagZeroResponses(t *testing.T) {
	a, b := handshakeConfigs(t)
	client, server, packets := driveSessions(t, a, b, false, false)
	now := time.Unix(1000, 0)
	if err := client.requestKeyUpdate(true, now); err != nil {
		t.Fatal(err)
	}
	if err := server.requestKeyUpdate(true, now); err != nil {
		t.Fatal(err)
	}
	outgoing := *packets
	*packets = nil
	if flags := collectKeyUpdateFlags(t, datagramsFrom(outgoing, true), client); !bytes.Equal(flags, []byte{1}) {
		t.Fatalf("client simultaneous flags = %v, want [1]", flags)
	}
	if flags := collectKeyUpdateFlags(t, datagramsFrom(outgoing, false), server); !bytes.Equal(flags, []byte{1}) {
		t.Fatalf("server simultaneous flags = %v, want [1]", flags)
	}
	for _, p := range outgoing {
		destination := client
		if p.fromClient {
			destination = server
		}
		if _, err := destination.receive(p.data, now); err != nil {
			t.Fatal(err)
		}
	}
	acks := *packets
	*packets = nil
	for _, p := range acks {
		destination := client
		if p.fromClient {
			destination = server
		}
		if _, err := destination.receive(p.data, now); err != nil {
			t.Fatal(err)
		}
	}
	responses := *packets
	*packets = nil
	clientFlags := collectKeyUpdateFlags(t, datagramsFrom(responses, true), client)
	serverFlags := collectKeyUpdateFlags(t, datagramsFrom(responses, false), server)
	if !bytes.Equal(clientFlags, []byte{0}) || !bytes.Equal(serverFlags, []byte{0}) {
		t.Fatalf("crossed update_requested responses = client %v server %v, want [0]", clientFlags, serverFlags)
	}
	for _, p := range responses {
		destination := client
		if p.fromClient {
			destination = server
		}
		if _, err := destination.receive(p.data, now); err != nil {
			t.Fatal(err)
		}
	}
	deliverSessionPackets(t, client, server, packets, now)
	if client.updating || server.updating || client.updatePending || server.updatePending {
		t.Fatal("simultaneous requests did not settle")
	}
	if err := client.application([]byte("settled")); err != nil {
		t.Fatal(err)
	}
	if data := deliverSessionPackets(t, client, server, packets, now); len(data) != 1 {
		t.Fatal("application exchange failed after simultaneous requests")
	}
}

func datagramsFrom(packets []testDatagram, fromClient bool) [][]byte {
	var out [][]byte
	for _, p := range packets {
		if p.fromClient == fromClient {
			out = append(out, p.data)
		}
	}
	return out
}

func TestRFC9147KeyUpdateFlagRejectsNonKeyUpdate(t *testing.T) {
	header := make([]byte, rfc9147HandshakeHeader+1)
	header[0] = msgFinished
	binary.BigEndian.PutUint16(header[2:4], 1)
	header[11] = 1
	if _, ok := rfc9147KeyUpdateFlag(header); ok {
		t.Fatal("Finished parsed as KeyUpdate")
	}
	header[0] = msgKeyUpdate
	header[rfc9147HandshakeHeader] = 2
	if _, ok := rfc9147KeyUpdateFlag(header); ok {
		t.Fatal("illegal KeyUpdateRequest parsed")
	}
}
