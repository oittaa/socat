package dtls13

import (
	"errors"
	"testing"
	"time"
)

func TestMTUSizeContract(t *testing.T) {
	if minPathMTU == ipv4MinPLPMTU || minPathMTU == ipv6MinPLPMTU || minPathMTU == ipv4MinReassemblyPLPMTU {
		t.Fatalf("handshake floor %d collided with an RFC PLPMTU", minPathMTU)
	}
	if ipv4MinPLPMTU != 40 || ipv6MinPLPMTU != 1232 || ipv4MinReassemblyPLPMTU != 548 {
		t.Fatalf("UDP-payload RFC mins: ipv4=%d ipv6=%d reassembly=%d", ipv4MinPLPMTU, ipv6MinPLPMTU, ipv4MinReassemblyPLPMTU)
	}
	if ipPacketSize(ipv4MinPLPMTU, false) != ipv4MinIPPacket || ipPacketSize(ipv6MinPLPMTU, true) != ipv6MinIPPacket {
		t.Fatal("IP conversion drifted from RFC 8899 MIN_PLPMTU")
	}
	if ipPacketSize(ipv4MinReassemblyPLPMTU, false) != ipv4MinReassemblyIP {
		t.Fatal("IPv4 reassembly conversion drifted")
	}
	if ipv4MinReassemblyIP != 576 || ipv6MinIPPacket != 1280 {
		t.Fatal("RFC 9147 ICMP-ignore IP floors drifted")
	}
	if defaultPLPMTU != 1200 {
		t.Fatalf("default dtls-mtu %d", defaultPLPMTU)
	}
	if datagramOverhead(0, defaultAEADTag) != 22 {
		t.Fatalf("no-CID AES overhead %d want 22", datagramOverhead(0, defaultAEADTag))
	}
	if rrcProbeOverhead(8, defaultAEADTag) != 39 {
		t.Fatalf("CID-8 RRC probe minimum %d want 39", rrcProbeOverhead(8, defaultAEADTag))
	}
}

func TestProbeTimeoutMeetsRFC8899(t *testing.T) {
	if probeTimeout < minProbeTimeout {
		t.Fatalf("probe timeout %s below RFC 8899 minimum %s", probeTimeout, minProbeTimeout)
	}
	if probeTimeout <= 15*time.Second {
		t.Fatalf("probe timeout %s is not larger than 15s", probeTimeout)
	}
	if probePace <= 0 {
		t.Fatal("probe pace must be positive")
	}
	if confirmTimer >= raiseTimer {
		t.Fatalf("confirm timer %s is not less than raise timer %s", confirmTimer, raiseTimer)
	}
	if raiseTimer != 600*time.Second {
		t.Fatalf("raise timer %s want 600s", raiseTimer)
	}
}

func TestRRCProbePaddingCIDOverhead(t *testing.T) {
	tag := defaultAEADTag
	for _, cidLen := range []int{0, 8, 32} {
		minSize := rrcProbeOverhead(cidLen, tag)
		for _, size := range []int{minSize, 256, 512, 1200} {
			if size < minSize {
				continue
			}
			pad, err := rrcProbePadding(size, cidLen, tag)
			if err != nil {
				t.Fatalf("cid=%d size=%d: %v", cidLen, size, err)
			}
			if minSize+pad != size {
				t.Fatalf("cid=%d size=%d pad=%d min=%d", cidLen, size, pad, minSize)
			}
		}
		if _, err := rrcProbePadding(minSize-1, cidLen, tag); err == nil {
			t.Fatalf("cid=%d accepted undersize probe", cidLen)
		}
	}
	if _, err := rrcProbePadding(1<<20, 0, tag); err == nil {
		t.Fatal("accepted a probe larger than the record limit")
	}
}

func TestRRCProbePaddingMatchesEncoderContentLimit(t *testing.T) {
	keys := testTrafficKeys(t)
	cid := []byte("cid-pad!")
	content := append([]byte{pathChallenge}, []byte("cookie08")...)
	tag := keys.aead.Overhead()
	maxPad := maxContent - rrcMessageLen
	size := rrcProbeOverhead(len(cid), tag) + maxPad
	if size != 16414 {
		t.Fatalf("CID-8 max probe datagram %d want 16414", size)
	}
	pad, err := rrcProbePadding(size, len(cid), tag)
	if err != nil {
		t.Fatal(err)
	}
	if pad != maxPad {
		t.Fatalf("pad %d want %d", pad, maxPad)
	}
	if rrcMessageLen+1+pad <= maxContent {
		t.Fatal("max padding does not include a content-type byte beyond maxContent")
	}
	if _, err := keys.encodeRecord(recordNumber{3, 1}, cid, contentRRC, content, pad); err != nil {
		t.Fatalf("encoder rejected maxContent padding: %v", err)
	}
	if _, err := rrcProbePadding(size+1, len(cid), tag); !errors.Is(err, errRecordOverflow) {
		t.Fatalf("accepted one byte past the encoder limit: %v", err)
	}
	if _, err := keys.encodeRecord(recordNumber{3, 2}, cid, contentRRC, content, maxPad+1); !errors.Is(err, errRecordOverflow) {
		t.Fatalf("encoder accepted oversized padding: %v", err)
	}
}
