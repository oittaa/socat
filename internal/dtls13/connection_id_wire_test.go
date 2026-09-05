package dtls13

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"slices"
	"testing"
	"time"
)

// RFC 9147 section 9: uint16 list length, uint8 CID lengths, then usage.
// These vectors deliberately do not use encodeCIDs or wireWriter.
func TestCIDRFCWire(t *testing.T) {
	longID := bytes.Repeat([]byte{0xa5}, 255)
	longWire := append([]byte{1, 0, 255}, longID...)
	longWire = append(longWire, 0)
	excess := []byte{0, 18, 1, 10, 1, 11, 1, 12, 1, 13, 1, 14, 1, 15, 1, 16, 1, 17, 1, 18, 1}
	firstEight := [][]byte{{10}, {11}, {12}, {13}, {14}, {15}, {16}, {17}}
	badSuffix := bytes.Clone(excess)
	badSuffix[18] = 2 // Truncated ninth CID must be checked despite the retention cap.
	for _, tc := range []struct {
		name      string
		wire      []byte
		ids       [][]byte
		immediate bool
		err       error
		canonical bool
	}{
		{"empty spare list", []byte{0, 0, 1}, nil, false, nil, true},
		{"empty CID spare", []byte{0, 1, 0, 1}, [][]byte{{}}, false, nil, true},
		{"empty CID immediate", []byte{0, 1, 0, 0}, [][]byte{{}}, true, nil, true},
		{"ordered immediate", []byte{0, 5, 1, 42, 2, 43, 44, 0}, [][]byte{{42}, {43, 44}}, true, nil, true},
		{"maximum CID", longWire, [][]byte{longID}, true, nil, true},
		{"duplicates", []byte{0, 6, 1, 42, 1, 42, 1, 43, 1}, [][]byte{{42}, {43}}, false, nil, false},
		{"excess", excess, firstEight, false, nil, false},
		{"bad suffix beyond cap", badSuffix, nil, false, errDecode, false},
		{"no header", nil, nil, false, errDecode, false},
		{"short list length", []byte{0}, nil, false, errDecode, false},
		{"missing usage", []byte{0, 0}, nil, false, errDecode, false},
		{"truncated list", []byte{0, 2, 0, 1}, nil, false, errDecode, false},
		{"truncated CID", []byte{0, 2, 2, 42, 1}, nil, false, errDecode, false},
		{"trailing byte", []byte{0, 0, 1, 0}, nil, false, errDecode, false},
		{"unknown usage", []byte{0, 0, 2}, nil, false, errIllegalParameter, false},
		{"reserved usage", []byte{0, 0, 255}, nil, false, errIllegalParameter, false},
		{"empty immediate list", []byte{0, 0, 0}, nil, false, errIllegalParameter, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ids, immediate, err := parseCIDs(tc.wire)
			if !errors.Is(err, tc.err) {
				t.Fatalf("parse %x: %v, want %v", tc.wire, err, tc.err)
			}
			if err != nil {
				return
			}
			if !slices.EqualFunc(ids, tc.ids, bytes.Equal) || immediate != tc.immediate {
				t.Fatalf("got %x, immediate=%t; want %x, immediate=%t", ids, immediate, tc.ids, tc.immediate)
			}
			if tc.canonical {
				encoded, err := encodeCIDs(tc.ids, tc.immediate)
				if err != nil || !bytes.Equal(encoded, tc.wire) {
					t.Fatalf("encoding = %x, %v; want %x", encoded, err, tc.wire)
				}
			}
		})
	}
	// A maximum-length list of empty CIDs still retains only one distinct ID.
	maxList := make([]byte, 65538)
	maxList[0], maxList[1], maxList[len(maxList)-1] = 255, 255, 1
	ids, _, err := parseCIDs(maxList)
	if err != nil || len(ids) != 1 || len(ids[0]) != 0 {
		t.Fatalf("maximum vector: %x, %v", ids, err)
	}
	maxList[len(maxList)-2] = 255
	if _, _, err := parseCIDs(maxList); !errors.Is(err, errDecode) {
		t.Fatalf("unchecked malformed suffix of maximum vector: %v", err)
	}
}

// Hand-author the DTLS handshake header too; only record protection uses the
// established session keys. The peer under test sees authenticated wire input.
func cidWireFragment(typ byte, sequence uint16, total, offset int, body []byte) []byte {
	wire := make([]byte, 12, 12+len(body))
	wire[0] = typ
	wire[1], wire[2], wire[3] = byte(total>>16), byte(total>>8), byte(total)
	binary.BigEndian.PutUint16(wire[4:6], sequence)
	wire[6], wire[7], wire[8] = byte(offset>>16), byte(offset>>8), byte(offset)
	wire[9], wire[10], wire[11] = byte(len(body)>>16), byte(len(body)>>8), byte(len(body))
	return append(wire, body...)
}

func sendCIDWire(t *testing.T, sender *session, typ byte, body []byte) {
	t.Helper()
	seq := uint16(sender.handshake.sequence)
	sender.handshake.sequence++
	if _, err := sender.sendRecord(sender.currentWriteEpoch(), contentHandshake, cidWireFragment(typ, seq, len(body), 0, body)); err != nil {
		t.Fatal(err)
	}
}

func TestCIDAuthenticatedWireErrors(t *testing.T) {
	for _, clientReceives := range []bool{true, false} {
		for _, tc := range []struct {
			name string
			typ  byte
			body []byte
			err  error
		}{
			{"empty request", msgRequestConnectionID, nil, errDecode},
			{"long request", msgRequestConnectionID, []byte{1, 0}, errDecode},
			{"truncated CID", msgNewConnectionID, []byte{0, 2, 2, 42, 1}, errDecode},
			{"trailing byte", msgNewConnectionID, []byte{0, 0, 1, 0}, errDecode},
			{"unknown usage", msgNewConnectionID, []byte{0, 0, 2}, errIllegalParameter},
			{"empty immediate", msgNewConnectionID, []byte{0, 0, 0}, errIllegalParameter},
		} {
			t.Run(fmt.Sprintf("client=%t/%s", clientReceives, tc.name), func(t *testing.T) {
				a, b := handshakeConfigs(t)
				client, server, packets := driveSessions(t, a, b, false, false)
				sender, receiver := client, server
				if clientReceives {
					sender, receiver = server, client
				}
				old := bytes.Clone(receiver.handshake.peerCID)
				sendCIDWire(t, sender, tc.typ, tc.body)
				if _, err := receiver.receive((*packets)[0].data, time.Unix(1000, 0)); !errors.Is(err, tc.err) {
					t.Fatalf("authenticated input returned %v, want alert %v", err, tc.err)
				}
				if !bytes.Equal(receiver.handshake.peerCID, old) || len(receiver.peerSpareCIDs) != 0 {
					t.Fatal("malformed input changed the CID pool")
				}
			})
		}
	}
}

func TestCIDEmptyRotationCanBeReplaced(t *testing.T) {
	for _, clientReceives := range []bool{true, false} {
		t.Run(fmt.Sprintf("client=%t", clientReceives), func(t *testing.T) {
			a, b := handshakeConfigs(t)
			client, server, packets := driveSessions(t, a, b, false, false)
			sender, receiver := client, server
			if clientReceives {
				sender, receiver = server, client
			}
			now := time.Unix(1000, 0)
			for _, cid := range [][]byte{nil, bytes.Repeat([]byte{42}, 255), {43}} {
				// A modeled peer can change its receiving CID length, including zero.
				body := []byte{byte((len(cid) + 1) >> 8), byte(len(cid) + 1), byte(len(cid))}
				body = append(append(body, cid...), 0)
				*packets = nil
				sendCIDWire(t, sender, msgNewConnectionID, body)
				packet := (*packets)[0]
				*packets = nil
				if _, err := receiver.receive(packet.data, now); err != nil {
					t.Fatalf("replace with %d-byte CID: %v", len(cid), err)
				}
				if len(cid) == 0 {
					if err := receiver.requestCIDs(1, now); !errors.Is(err, errUnexpectedMessage) {
						t.Fatalf("request while sending empty CID: %v", err)
					}
				}
				if err := receiver.application([]byte("after rotation")); err != nil {
					t.Fatal(err)
				}
				if len(*packets) != 2 {
					t.Fatalf("outgoing records = %d, want ACK and application", len(*packets))
				}
				for i, out := range *packets {
					r, tail, err := parseRecord(out.data, len(cid))
					if err != nil || len(tail) != 0 || !bytes.Equal(r.cid, cid) {
						t.Fatalf("record %d did not use new CID: %x, %v", i, r.cid, err)
					}
					var window replayWindow
					_, typ, data, err := sender.read[3].keys.decodeRecord(r, 3, cid, &window)
					if err != nil || i == 1 && (typ != contentData || string(data) != "after rotation") {
						t.Fatalf("record %d did not authenticate: type=%d, %q, %v", i, typ, data, err)
					}
				}
			}
		})
	}
}

func TestCIDAuthenticatedPoolBounds(t *testing.T) {
	for _, clientReceives := range []bool{true, false} {
		t.Run(fmt.Sprintf("client=%t", clientReceives), func(t *testing.T) {
			a, b := handshakeConfigs(t)
			client, server, packets := driveSessions(t, a, b, false, false)
			sender, receiver := client, server
			if clientReceives {
				sender, receiver = server, client
			}
			// 511 list bytes: one zero-length CID, then 255 one-byte CIDs.
			body := []byte{1, 255, 0}
			for i := 1; i <= 255; i++ {
				body = append(body, 1, byte(i))
			}
			body = append(body, 1)
			for range 2 {
				*packets = nil
				sendCIDWire(t, sender, msgNewConnectionID, body)
				if _, err := receiver.receive((*packets)[0].data, time.Unix(1000, 0)); err != nil {
					t.Fatal(err)
				}
				want := [][]byte{{}, {1}, {2}, {3}, {4}, {5}, {6}, {7}}
				if !slices.EqualFunc(receiver.peerSpareCIDs, want, bytes.Equal) {
					t.Fatalf("bounded/deduplicated spare order: %x", receiver.peerSpareCIDs)
				}
			}
			body[len(body)-3] = 2 // Bad CID length after all retained identifiers.
			*packets = nil
			sendCIDWire(t, sender, msgNewConnectionID, body)
			if _, err := receiver.receive((*packets)[0].data, time.Unix(1000, 0)); !errors.Is(err, errDecode) {
				t.Fatalf("authenticated malformed excess CID: %v", err)
			}
		})
	}
}

func TestCIDFragmentResourceBounds(t *testing.T) {
	a, b := handshakeConfigs(t)
	client, server, packets := driveSessions(t, a, b, false, false)
	const total = 65538 // Largest NewConnectionId body allowed by its wire vector.
	cost := fragmentCost(total)
	budget := &memoryBudget{limit: int64(2 * cost)}
	server.reassembly.budget = budget
	next := uint16(client.handshake.sequence)
	for i := 1; i <= 2*maxPendingMessages; i++ {
		wire := cidWireFragment(msgNewConnectionID, next+uint16(i), total, 0, []byte{255})
		*packets = nil
		if _, err := client.sendRecord(3, contentHandshake, wire); err != nil {
			t.Fatal(err)
		}
		if _, err := server.receive((*packets)[0].data, time.Unix(1000, 0)); err != nil {
			t.Fatal(err)
		}
		if budget.used.Load() > int64(2*cost) || server.reassembly.buffered > 2*total || len(server.reassembly.pending) > 2 {
			t.Fatal("CID fragments bypassed shared memory/message bounds")
		}
	}
	if budget.used.Load() != int64(2*cost) || len(server.reassembly.pending) != 2 {
		t.Fatal("test did not fill the configured fragment budget")
	}
	wire := cidWireFragment(msgNewConnectionID, next, maxHandshakeBody+1, 0, []byte{0})
	*packets = nil
	if _, err := client.sendRecord(3, contentHandshake, wire); err != nil {
		t.Fatal(err)
	}
	if _, err := server.receive((*packets)[0].data, time.Unix(1000, 0)); !errors.Is(err, errHandshakeLimit) {
		t.Fatalf("oversized CID handshake allocation: %v", err)
	}
	server.reassembly.clear()
	if budget.used.Load() != 0 {
		t.Fatal("CID fragment reservations leaked on cleanup")
	}
}
