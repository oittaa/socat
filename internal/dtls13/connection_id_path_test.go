package dtls13

import (
	"bytes"
	"fmt"
	"net/netip"
	"testing"
	"time"
)

func (p *testPaths) settleCID(t *testing.T, now time.Time) time.Time {
	t.Helper()
	for range 100 {
		p.deliver(t, now)
		next := p.client.deadline()
		if candidate := p.server.deadline(); next.IsZero() || !candidate.IsZero() && candidate.Before(next) {
			next = candidate
		}
		if next.IsZero() {
			return now
		}
		now = next
		for _, s := range []*session{p.client, p.server} {
			if err := s.tick(now); err != nil {
				t.Fatal(err)
			}
		}
	}
	t.Fatal("path/CID flights exceeded deterministic event bound")
	return now
}

func TestCIDRepeatedMigrationAndProbeExpiry(t *testing.T) {
	for _, clientMoves := range []bool{true, false} {
		t.Run(fmt.Sprintf("client=%t", clientMoves), func(t *testing.T) {
			p := newTestPaths(t)
			now := time.Unix(1000, 0)
			for _, s := range []*session{p.client, p.server} {
				if err := s.requestCIDs(255, now); err != nil {
					t.Fatal(err)
				}
			}
			now = p.settleCID(t, now)
			mover, observer, address := p.client, p.server, &p.clientAddress
			if !clientMoves {
				mover, observer, address = p.server, p.client, &p.serverAddress
			}
			// Exhaust both spare pools, including a consumed but unvalidated CID.
			for attempt := range maxConnectionIDs + 2 {
				oldAddress := *address
				oldCID := bytes.Clone(observer.handshake.peerCID)
				reserved := oldCID
				if len(observer.peerSpareCIDs) != 0 {
					reserved = bytes.Clone(observer.peerSpareCIDs[0])
				}
				mover.useSpareCID()
				*address = netip.AddrPortFrom(oldAddress.Addr(), uint16(3000+attempt))
				if err := mover.application([]byte("moved")); err != nil {
					t.Fatal(err)
				}
				p.deliver(t, now)
				if observer.path.probe == nil || !observer.path.probe.old {
					t.Fatal("new path did not start enhanced validation")
				}
				now = observer.path.probe.deadline
				if err := observer.tick(now); err != nil {
					t.Fatal(err)
				}
				if observer.path.probe == nil || observer.path.probe.old || len(p.packets) == 0 {
					t.Fatal("old path expiry did not reserve a new-path CID")
				}
				r, _, err := parseRecord(p.packets[0].data, len(mover.handshake.localCID))
				if err != nil || !bytes.Equal(r.cid, reserved) || r.number.epoch != observer.currentWriteEpoch()&3 {
					t.Fatalf("candidate challenge CID/epoch: %x, %v", r.cid, err)
				}
				failed := attempt == 2
				if failed {
					p.packets = nil // Lose the candidate challenge and let the probe expire.
					*address = oldAddress
					now = observer.path.probe.deadline
					if err := observer.tick(now); err != nil {
						t.Fatal(err)
					}
					if !bytes.Equal(observer.handshake.peerCID, oldCID) || containsCID(observer.peerSpareCIDs, reserved) {
						t.Fatal("failed probe changed active CID or recycled its reserved spare")
					}
				} else {
					// KeyUpdates travel while the challenge/response is still in flight.
					for _, s := range []*session{mover, observer} {
						if err := s.requestKeyUpdate(false, now); err != nil {
							t.Fatal(err)
						}
					}
				}
				now = p.settleCID(t, now)
				if observer.path.probe != nil || observer.path.peer.remote != *address || !failed && !bytes.Equal(observer.handshake.peerCID, reserved) {
					t.Fatal("path validation installed the wrong address/CID")
				}
				for _, s := range []*session{mover, observer} {
					if len(s.localCIDs) != maxConnectionIDs || len(s.peerSpareCIDs) > maxConnectionIDs || len(s.post) != 0 || s.cidRequested {
						t.Fatal("migration grew pools or left a CID exchange pending")
					}
					if err := s.application([]byte("after migration")); err != nil {
						t.Fatal(err)
					}
				}
				data := p.deliver(t, now)
				if len(data) != 2 || string(data[0]) != "after migration" || !bytes.Equal(data[0], data[1]) {
					t.Fatal("migration/KeyUpdate lost application data")
				}
			}
			if len(mover.peerSpareCIDs) != 0 || len(observer.peerSpareCIDs) != 0 {
				t.Fatal("test did not exhaust the spare pools")
			}
		})
	}
}
